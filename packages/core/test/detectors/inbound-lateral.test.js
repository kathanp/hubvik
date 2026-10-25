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
    dstIp: '10.0.0.2',
    dstPort: 80,
    proto: 'tcp',
    direction: 'lan',
    bytesOut: 200,
    bytesIn: 200,
    pktsOut: 2,
    pktsIn: 2,
    durationMs: 20,
    tcpOutcome: 'established',
    ...extra,
  };
}

/**
 * @param {number} ts
 */
function inbound(ts) {
  return flow({
    ts,
    direction: 'in',
    srcIp: '8.8.8.8',
    dstIp: '10.0.0.8',
    dstPort: 554,
  });
}

/**
 * @param {import('node:events').EventEmitter} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'inbound-lateral') hits.push(row);
  });
  return hits;
}

test('inbound-lateral fires on the third new LAN peer inside 300000 ms', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  engine.feed(inbound(0));
  engine.feed(flow({ ts: 300000, dstIp: '10.0.0.2' }));
  engine.feed(flow({ ts: 300000, dstIp: '10.0.0.3' }));
  assert.strictEqual(hits.length, 0);
  engine.feed(flow({ ts: 300000, dstIp: '10.0.0.4' }));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.peers.length, 3);

  const late = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const lateHits = hitsOf(late);
  late.feed(inbound(0));
  late.feed(flow({ ts: 300001, dstIp: '10.0.0.2' }));
  late.feed(flow({ ts: 300001, dstIp: '10.0.0.3' }));
  late.feed(flow({ ts: 300001, dstIp: '10.0.0.4' }));
  assert.deepStrictEqual(lateHits, []);
});

test('inbound-lateral ignores a documentation address, a learned peer, and multicast', () => {
  const doc = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const docHits = hitsOf(doc);
  doc.feed(flow({ ts: 0, direction: 'in', srcIp: '192.0.2.10', dstIp: '10.0.0.8' }));
  for (let i = 2; i <= 4; i += 1) doc.feed(flow({ ts: 1000, dstIp: `10.0.0.${i}` }));
  assert.deepStrictEqual(docHits, []);

  const learning = createEngine({ shadow: true, learnMs: 10_000, tiers: ['T1'] });
  for (let i = 2; i <= 4; i += 1) learning.feed(flow({ ts: 1000, dstIp: `10.0.0.${i}` }));
  const hits = hitsOf(learning);
  learning.feed(inbound(20_000));
  for (let i = 2; i <= 4; i += 1) learning.feed(flow({ ts: 21_000, dstIp: `10.0.0.${i}` }));
  assert.deepStrictEqual(hits, []);
  for (let i = 5; i <= 7; i += 1) learning.feed(flow({ ts: 22_000, dstIp: `10.0.0.${i}` }));
  assert.strictEqual(hits.length, 1);

  const group = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const groupHits = hitsOf(group);
  group.feed(inbound(0));
  group.feed(flow({ ts: 1000, dstIp: '239.255.255.250', proto: 'udp' }));
  group.feed(flow({ ts: 1000, dstIp: '10.0.0.2' }));
  group.feed(flow({ ts: 1000, dstIp: '10.0.0.3' }));
  assert.deepStrictEqual(groupHits, []);
});

test('inbound-lateral keeps the newest eight inbound sessions', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (let i = 0; i < 8; i += 1) engine.feed(inbound(i));
  engine.feed(inbound(8));
  engine.feed(flow({ ts: 300008, dstIp: '10.0.0.2' }));
  engine.feed(flow({ ts: 300008, dstIp: '10.0.0.3' }));
  engine.feed(flow({ ts: 300008, dstIp: '10.0.0.4' }));
  assert.strictEqual(hits.length, 1);

  const dropped = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const droppedHits = hitsOf(dropped);
  for (let i = 0; i < 8; i += 1) dropped.feed(inbound(i));
  dropped.feed(flow({ ts: 300008, dstIp: '10.0.0.2' }));
  dropped.feed(flow({ ts: 300008, dstIp: '10.0.0.3' }));
  dropped.feed(flow({ ts: 300008, dstIp: '10.0.0.4' }));
  assert.deepStrictEqual(droppedHits, []);
});

test('inbound-lateral rejects an over-cap learned list and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  engine.feed(inbound(0));
  engine.feed(flow({ ts: 1000, dstIp: '10.0.0.2' }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 5001; i += 1) learned.push(`10.1.0.${i}`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'inbound-lateral': {
              v: 1,
              state: { learned, inbound: [], peers: [], peerSince: null, fired: false },
            },
          },
        },
      },
    });
  }, /exceeds cap/);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'inbound-lateral': {
              v: 1,
              state: {
                ...saved.devices.cam.detectors['inbound-lateral'].state,
                constructor: { no: true },
              },
            },
          },
        },
      },
    });
  }, /forbidden key/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  next.feed(flow({ ts: 2000, dstIp: '10.0.0.3' }));
  next.feed(flow({ ts: 2000, dstIp: '10.0.0.4' }));
  assert.strictEqual(hits.length, 1);
});

test('inbound-lateral is silent while learning', () => {
  const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T1'] });
  const hits = hitsOf(engine);
  engine.feed(inbound(0));
  engine.feed(flow({ ts: 1000, dstIp: '10.0.0.2' }));
  engine.feed(flow({ ts: 1000, dstIp: '10.0.0.3' }));
  engine.feed(flow({ ts: 1000, dstIp: '10.0.0.4' }));
  assert.deepStrictEqual(hits, []);
});

test('inbound-lateral is silent on 14-day benign traffic for every device class', () => {
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
