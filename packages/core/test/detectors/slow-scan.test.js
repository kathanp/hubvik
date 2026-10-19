'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { scenarios } = require('../../../../eval/evasion-holdout/scenarios.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    device: 'd',
    ts: 0,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '9.9.9.9',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 40,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 10,
    ...extra,
  };
}

test('slow-scan emits shadow-anomaly on the holdout and ignores multicast', () => {
  const scenario = scenarios().find((row) => row.id === 'holdout-slow-scan');
  assert.ok(scenario);
  const engine = createEngine({
    learnMs: scenario.events[scenario.learnCount - 1].ts + 1,
    tiers: ['T1'],
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'slow-scan') hits.push(row);
  });
  for (const event of scenario.events) engine.feed(event);
  engine.flush(scenario.events[scenario.events.length - 1].ts + 3600e3);
  assert.ok(hits.length >= 1);
  assert.strictEqual(hits[0].severity, 'high');
  engine.feed(
    flow({
      ts: scenario.events[scenario.events.length - 1].ts + 1000,
      dstIp: '239.255.255.250',
      dstPort: 1900,
      proto: 'udp',
    }),
  );
  assert.strictEqual(hits.length, 1);
});

test('slow-scan learned-pair cap drops the next destination', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T1'], maxDestinations: 2 });
  engine.feed(flow({ ts: 0, dstIp: '9.9.0.1', dstPort: 1 }));
  engine.feed(flow({ ts: 1, dstIp: '9.9.0.2', dstPort: 2 }));
  engine.feed(flow({ ts: 2, dstIp: '9.9.0.3', dstPort: 3 }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.strictEqual(saved.devices.d.detectors['slow-scan'].state.pairs.length, 2);
  assert.throws(
    () =>
      engine.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              'slow-scan': {
                v: 1,
                state: {
                  pairs: ['a:1', 'b:2', 'c:3'],
                  day: 0,
                  today: 3,
                  daily: { count: 0, mean: 0, m2: 0, min: 0, max: 0 },
                },
              },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('slow-scan restores the learned daily max', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T1'] });
  engine.feed(flow({ ts: 0, dstIp: '9.9.0.1', dstPort: 80 }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const next = createEngine({ learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 2 });
  assert.deepStrictEqual(again.devices.d.detectors['slow-scan'].state.pairs, ['9.9.0.1:80']);
});

test('slow-scan is silent on the all-tier benign matrix', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({
        profile,
        days: 14,
        seed,
        startTs: T0,
        rich: true,
        discovery: true,
        ipv6: true,
      });
      const engine = createEngine({ learnMs: 7 * DAY, tiers: TIERS, identity: 'auto' });
      engine.setDeviceClass(events[0].device, profile);
      /** @type {any[]} */
      const hits = [];
      engine.on('shadow-anomaly', (row) => {
        if (
          row.detector === 'slow-scan' &&
          (row.severity === 'medium' || row.severity === 'high' || row.severity === 'critical')
        ) {
          hits.push(row);
        }
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepStrictEqual(hits, [], `${profile} seed ${seed}`);
    }
  }
});
