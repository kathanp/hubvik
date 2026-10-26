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
function tls(extra) {
  return {
    type: 'tls',
    device: 'cam',
    ts: 1000,
    dstIp: '9.9.9.9',
    dstPort: 443,
    sni: 'cdn.example',
    alpn: ['h2'],
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
  for (let i = 1; i <= count; i += 1) {
    events.push(
      tls({ dstIp: `9.9.${Math.floor((i - 1) / 250)}.${((i - 1) % 250) + 1}`, ...extra }),
    );
  }
  return events;
}

/**
 * @param {import('node:events').EventEmitter} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'h2-fanout') hits.push(row);
  });
  engine.on('anomaly', (row) => {
    if (row.detector === 'h2-fanout') hits.push(row);
  });
  return hits;
}

test('h2-fanout fires at 64 new HTTP/2 destinations and stays quiet at 63', () => {
  const quiet = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const quietHits = hitsOf(quiet);
  for (const event of many(63)) quiet.feed(event);
  assert.strictEqual(quietHits.length, 0);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const hits = hitsOf(engine);
  for (const event of many(64)) engine.feed(event);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.destinations, 64);
  engine.feed(tls({ dstIp: '9.9.9.200' }));
  assert.strictEqual(hits.length, 1);
});

test('h2-fanout ignores a missing h2 token, a bogon, and a learned destination', () => {
  const plain = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const plainHits = hitsOf(plain);
  for (const event of many(64, { alpn: ['http/1.1'] })) plain.feed(event);
  for (const event of many(64, { alpn: ['h2c'] })) plain.feed(event);
  plain.feed(tls({ dstIp: '192.0.2.10' }));
  plain.feed(tls({ dstIp: '239.255.255.250' }));
  assert.deepStrictEqual(plainHits, []);

  const learning = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T3'] });
  const learningHits = hitsOf(learning);
  for (const event of many(64)) learning.feed(event);
  assert.deepStrictEqual(learningHits, []);
  learning.lock('cam');
  for (const event of many(64, { ts: 90_000_000 })) learning.feed(event);
  assert.deepStrictEqual(learningHits, []);
  for (let i = 1; i <= 64; i += 1) learning.feed(tls({ ts: 90_000_000, dstIp: `8.8.${i}.1` }));
  assert.strictEqual(learningHits.length, 1);
});

test('h2-fanout stays off when shadow is false, caps destinations, and restores', () => {
  const off = createEngine({ shadow: false, learnMs: 0, tiers: ['T3'] });
  const offHits = hitsOf(off);
  for (const event of many(64)) off.feed(event);
  assert.deepStrictEqual(offHits, []);

  const capped = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'], maxDestinations: 4 });
  const cappedHits = hitsOf(capped);
  for (const event of many(64)) capped.feed(event);
  assert.deepStrictEqual(cappedHits, []);
  const saved = capped.exportBaseline({ createdAt: 1 });
  assert.strictEqual(saved.devices.cam.detectors['h2-fanout'].state.dests.length, 4);
  assert.throws(() => {
    capped.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'h2-fanout': {
              v: 1,
              state: {
                learned: [],
                win: 0,
                fired: false,
                dests: ['1.1.1.1', '1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5'],
              },
            },
          },
        },
      },
    });
  }, /exceeds cap/);
  const bad = { ...saved.devices.cam.detectors['h2-fanout'].state, constructor: { no: true } };
  assert.throws(() => {
    capped.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'h2-fanout': { v: 1, state: bad } },
        },
      },
    });
  }, /forbidden key/);

  const partial = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  for (const event of many(63)) partial.feed(event);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  next.importBaseline(partial.exportBaseline({ createdAt: 2 }));
  const restored = hitsOf(next);
  next.feed(tls({ dstIp: '8.8.8.8' }));
  assert.strictEqual(restored.length, 1);
});

test('h2-fanout is silent on 14-day benign traffic for every device class', () => {
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
