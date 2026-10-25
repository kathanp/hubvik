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
    dstPort: 27015,
    proto: 'udp',
    direction: 'out',
    bytesOut: 1000,
    bytesIn: 0,
    pktsOut: 20,
    pktsIn: 0,
    durationMs: 10,
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
      flow({ dstIp: `9.9.${Math.floor((i - 1) / 250)}.${((i - 1) % 250) + 1}`, ...extra }),
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
    if (row.detector === 'scatter-udp') hits.push(row);
  });
  engine.on('anomaly', (row) => {
    if (row.detector === 'scatter-udp') hits.push(row);
  });
  return hits;
}

test('scatter-udp fires at 40 destinations of 20 packets and stays quiet one step outside', () => {
  const quiet = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const quietHits = hitsOf(quiet);
  for (const event of many(39)) quiet.feed(event);
  assert.strictEqual(quietHits.length, 0);

  const short = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const shortHits = hitsOf(short);
  for (const event of many(40, { pktsOut: 19 })) short.feed(event);
  assert.deepStrictEqual(shortHits, []);

  const owned = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const ownedHits = hitsOf(owned);
  for (const event of many(40, { pktsOut: 200 })) owned.feed(event);
  assert.deepStrictEqual(ownedHits, []);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (const event of many(40, { pktsOut: 199 })) engine.feed(event);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.destinations, 40);
  assert.strictEqual(hits[0].data.packets, 7960);
});

test('scatter-udp ignores a two-way ratio, DNS, NTP, and a learned destination', () => {
  const ratio = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const ratioHits = hitsOf(ratio);
  for (const event of many(40, { bytesIn: 50 })) ratio.feed(event);
  assert.deepStrictEqual(ratioHits, []);

  const under = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const underHits = hitsOf(under);
  for (const event of many(40, { bytesIn: 49 })) under.feed(event);
  assert.strictEqual(underHits.length, 1);

  const dns = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const dnsHits = hitsOf(dns);
  for (const event of many(40, { dstPort: 53 })) dns.feed(event);
  for (const event of many(40, { dstPort: 123 })) dns.feed(event);
  assert.deepStrictEqual(dnsHits, []);

  const learning = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T1'] });
  const learningHits = hitsOf(learning);
  for (const event of many(40)) learning.feed(event);
  assert.deepStrictEqual(learningHits, []);
  learning.lock('cam');
  for (const event of many(40, { ts: 90_000_000 })) learning.feed(event);
  assert.deepStrictEqual(learningHits, []);
});

test('scatter-udp stays off when shadow is false, caps rows, and restores', () => {
  const off = createEngine({ shadow: false, learnMs: 0, tiers: ['T1'] });
  const offHits = hitsOf(off);
  for (const event of many(40)) off.feed(event);
  assert.deepStrictEqual(offHits, []);

  const capped = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], maxDestinations: 4 });
  const cappedHits = hitsOf(capped);
  for (const event of many(40)) capped.feed(event);
  assert.deepStrictEqual(cappedHits, []);
  const saved = capped.exportBaseline({ createdAt: 1 });
  assert.strictEqual(saved.devices.cam.detectors['scatter-udp'].state.rows.length, 4);
  assert.throws(() => {
    capped.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'scatter-udp': {
              v: 1,
              state: {
                learned: [],
                win: 0,
                fired: false,
                rows: [1, 2, 3, 4, 5].map((n) => ({
                  ip: `9.9.0.${n}`,
                  pkts: 20,
                  out: 1000,
                  inn: 0,
                })),
              },
            },
          },
        },
      },
    });
  }, /exceeds cap/);
  const bad = { ...saved.devices.cam.detectors['scatter-udp'].state, constructor: { no: true } };
  assert.throws(() => {
    capped.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'scatter-udp': { v: 1, state: bad } },
        },
      },
    });
  }, /forbidden key/);

  const partial = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  for (const event of many(39)) partial.feed(event);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  next.importBaseline(partial.exportBaseline({ createdAt: 2 }));
  const restored = hitsOf(next);
  next.feed(flow({ dstIp: '8.8.8.8' }));
  assert.strictEqual(restored.length, 1);
});

test('scatter-udp is silent on 14-day benign traffic for every device class', () => {
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
