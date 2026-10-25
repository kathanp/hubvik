'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
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
    device: 'cam',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '9.9.9.9',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 1000,
    bytesIn: 0,
    pktsOut: 1000,
    pktsIn: 0,
    durationMs: 10,
    ...extra,
  };
}

/**
 * @param {import('node:events').EventEmitter} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'dispersed-flood') hits.push(row);
  });
  return hits;
}

test('dispersed-flood fires when eight one-way destinations share a window', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (let i = 0; i < 7; i += 1) engine.feed(flow({ dstIp: `9.9.9.${i + 1}` }));
  assert.strictEqual(hits.length, 0);
  engine.feed(flow({ dstIp: '9.9.9.8' }));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.destinations, 8);
  assert.strictEqual(hits[0].data.packets, 8000);
  engine.feed(flow({ dstIp: '9.9.9.9' }));
  assert.strictEqual(hits.length, 1);
});

test('dispersed-flood stays quiet on a two-way ratio and on an egress-flood sized destination', () => {
  const ratio = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const ratioHits = hitsOf(ratio);
  for (let i = 0; i < 8; i += 1) {
    ratio.feed(flow({ dstIp: `9.9.1.${i + 1}`, bytesOut: 1000, bytesIn: 50 }));
  }
  assert.deepStrictEqual(ratioHits, []);

  const under = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const underHits = hitsOf(under);
  for (let i = 0; i < 8; i += 1) {
    under.feed(flow({ dstIp: `9.9.2.${i + 1}`, bytesOut: 1000, bytesIn: 49 }));
  }
  assert.strictEqual(underHits.length, 1);

  const owned = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const ownedHits = hitsOf(owned);
  for (let i = 0; i < 8; i += 1) {
    owned.feed(flow({ dstIp: `9.9.3.${i + 1}`, pktsOut: 50000 }));
  }
  assert.deepStrictEqual(ownedHits, []);

  const edge = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const edgeHits = hitsOf(edge);
  for (let i = 0; i < 8; i += 1) {
    edge.feed(flow({ dstIp: `9.9.4.${i + 1}`, pktsOut: 49999 }));
  }
  assert.strictEqual(edgeHits.length, 1);
});

test('dispersed-flood is silent while learning and ignores a group address', () => {
  const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (let i = 0; i < 8; i += 1) engine.feed(flow({ ts: 1000 + i, dstIp: `9.9.5.${i + 1}` }));
  engine.feed(flow({ dstIp: '239.255.255.250', proto: 'udp' }));
  assert.deepStrictEqual(hits, []);
});

test('dispersed-flood caps destinations and restores the open window', () => {
  const engine = createEngine({
    shadow: true,
    learnMs: 0,
    tiers: ['T1'],
    maxDestinations: 4,
  });
  const hits = hitsOf(engine);
  for (let i = 0; i < 8; i += 1) engine.feed(flow({ dstIp: `9.9.6.${i + 1}` }));
  assert.deepStrictEqual(hits, []);
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.strictEqual(saved.devices.cam.detectors['dispersed-flood'].state.rows.length, 4);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'dispersed-flood': {
              v: 1,
              state: {
                win: 0,
                fired: false,
                rows: [1, 2, 3, 4, 5].map((n) => ({ ip: `9.9.0.${n}`, pkts: 1, out: 1, inn: 0 })),
              },
            },
          },
        },
      },
    });
  }, /exceeds cap/);
  const bad = {
    ...saved.devices.cam.detectors['dispersed-flood'].state,
    constructor: { no: true },
  };
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'dispersed-flood': { v: 1, state: bad } },
        },
      },
    });
  }, /forbidden key/);

  const partial = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  for (let i = 0; i < 7; i += 1) partial.feed(flow({ dstIp: `9.9.7.${i + 1}` }));
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  next.importBaseline(partial.exportBaseline({ createdAt: 2 }));
  const restored = hitsOf(next);
  next.feed(flow({ dstIp: '9.9.7.8' }));
  assert.strictEqual(restored.length, 1);
});

test('dispersed-flood is silent on 14-day benign traffic for every device class', () => {
  for (const profile of CLASS_NAMES) {
    const events = simulate({
      profile,
      days: 14,
      seed: 1,
      startTs: T0,
      rich: true,
      discovery: true,
      ipv6: true,
    });
    const engine = createEngine({
      shadow: true,
      learnMs: 7 * DAY,
      tiers: TIERS,
      identity: 'auto',
    });
    engine.setDeviceClass(events[0].device, profile);
    const hits = hitsOf(engine);
    for (const event of events) engine.feed(event);
    engine.flush(T0 + 14 * DAY);
    assert.deepStrictEqual(
      hits.filter((row) => row.severity !== 'info' && row.severity !== 'low'),
      [],
      profile,
    );
  }
});
