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
    bytesOut: 120,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 10,
    ...extra,
  };
}

test('jitter-beacon emits shadow-anomaly on the holdout', () => {
  const scenario = scenarios().find((row) => row.id === 'holdout-beacon-45');
  assert.ok(scenario);
  const engine = createEngine({
    learnMs: scenario.events[scenario.learnCount - 1].ts + 1,
    tiers: ['T1'],
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'jitter-beacon') hits.push(row);
  });
  for (const event of scenario.events) engine.feed(event);
  engine.flush(scenario.events[scenario.events.length - 1].ts + 1000);
  assert.ok(hits.length >= 1);
  assert.strictEqual(hits[0].severity, 'high');
});

test('jitter-beacon keeps 64 destinations and rejects a 65th on import', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1'] });
  for (let i = 0; i < 65; i += 1) engine.feed(flow({ ts: i, dstIp: `9.9.1.${i}` }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.strictEqual(saved.devices.d.detectors['jitter-beacon'].state.tracks.length, 64);
  assert.throws(() => {
    const tracks = [];
    for (let i = 0; i < 65; i += 1) {
      tracks.push([
        `9.9.2.${i}`,
        {
          buckets: new Array(16).fill(0),
          count: 1,
          gaps: 0,
          first: 0,
          last: 0,
          min: 1,
          max: 1,
          fired: false,
        },
      ]);
    }
    engine.importBaseline({
      ...saved,
      devices: {
        d: {
          ...saved.devices.d,
          detectors: {
            'jitter-beacon': { v: 1, state: { baseline: [], tracks } },
          },
        },
      },
    });
  }, /exceeds cap/);
});

test('jitter-beacon restores a track', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1'] });
  engine.feed(flow({ ts: 0 }));
  engine.feed(flow({ ts: 300000 }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const next = createEngine({ learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 2 });
  assert.strictEqual(again.devices.d.detectors['jitter-beacon'].state.tracks.length, 1);
});

test('jitter-beacon is silent on the all-tier benign matrix', () => {
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
        if (row.detector === 'jitter-beacon' && row.severity !== 'low' && row.severity !== 'info')
          hits.push(row.detector);
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepStrictEqual(hits, [], `${profile} seed ${seed}`);
    }
  }
});
