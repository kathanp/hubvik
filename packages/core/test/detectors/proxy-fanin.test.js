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
    srcIp: '8.8.8.8',
    srcPort: 50000,
    dstIp: '10.0.0.8',
    dstPort: 1080,
    proto: 'tcp',
    direction: 'in',
    bytesOut: 200,
    bytesIn: 800,
    pktsOut: 4,
    pktsIn: 6,
    durationMs: 40,
    tcpOutcome: 'established',
    ...extra,
  };
}

/**
 * @param {number} count
 * @param {Record<string, unknown>} [extra]
 */
function many(count, extra) {
  /** @type {Record<string, unknown>[]} */
  const events = [];
  for (let i = 1; i <= count; i += 1) events.push(flow({ srcIp: `8.8.8.${i}`, ...extra }));
  return events;
}

/**
 * @param {import('node:events').EventEmitter} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'proxy-fanin') hits.push(row);
  });
  engine.on('anomaly', (row) => {
    if (row.detector === 'proxy-fanin') hits.push(row);
  });
  return hits;
}

test('proxy-fanin fires at 8 new clients and stays quiet at 7', () => {
  const quiet = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const quietHits = hitsOf(quiet);
  for (const event of many(7)) quiet.feed(event);
  assert.strictEqual(quietHits.length, 0);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (const event of many(8)) engine.feed(event);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.peers, 8);
  engine.feed(flow({ srcIp: '8.8.8.9' }));
  assert.strictEqual(hits.length, 1);
});

test('proxy-fanin ignores a scan, a low port, a bogon, and a one-way session', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (const event of many(8, { tcpOutcome: 'no-response' })) engine.feed(event);
  for (const event of many(8, { dstPort: 1024 })) engine.feed(event);
  for (const event of many(8, { dstPort: 1025, bytesIn: 0 })) engine.feed(event);
  for (const event of many(8, { srcIp: '192.0.2.10' })) engine.feed(event);
  assert.deepStrictEqual(hits, []);
  for (const event of many(8, { dstPort: 1025 })) engine.feed(event);
  assert.strictEqual(hits.length, 1);
});

test('proxy-fanin is silent while learning, stays off when shadow is false, and restores', () => {
  const learning = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T1'] });
  const learningHits = hitsOf(learning);
  for (const event of many(8)) learning.feed(event);
  assert.deepStrictEqual(learningHits, []);
  learning.lock('cam');
  for (const event of many(8, { ts: 90_000_000 })) learning.feed(event);
  assert.deepStrictEqual(learningHits, []);

  const off = createEngine({ shadow: false, learnMs: 0, tiers: ['T1'] });
  const offHits = hitsOf(off);
  for (const event of many(8)) off.feed(event);
  assert.deepStrictEqual(offHits, []);

  const capped = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], maxDestinations: 4 });
  const cappedHits = hitsOf(capped);
  for (const event of many(8)) capped.feed(event);
  assert.deepStrictEqual(cappedHits, []);
  const saved = capped.exportBaseline({ createdAt: 1 });
  assert.throws(() => {
    capped.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'proxy-fanin': {
              v: 1,
              state: {
                learned: [],
                win: 0,
                fired: false,
                peers: ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5'],
              },
            },
          },
        },
      },
    });
  }, /exceeds cap/);
  const bad = { ...saved.devices.cam.detectors['proxy-fanin'].state, constructor: { no: true } };
  assert.throws(() => {
    capped.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'proxy-fanin': { v: 1, state: bad } },
        },
      },
    });
  }, /forbidden key/);

  const partial = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  for (const event of many(7)) partial.feed(event);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  next.importBaseline(partial.exportBaseline({ createdAt: 2 }));
  const restored = hitsOf(next);
  next.feed(flow({ srcIp: '8.8.4.4' }));
  assert.strictEqual(restored.length, 1);
});

test('proxy-fanin is silent on 14-day benign traffic for every device class', () => {
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
