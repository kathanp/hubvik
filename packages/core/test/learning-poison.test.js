'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const POISON = ['ramp', 'late-family-burst', 'beacon-born-in-learning'];

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 0,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    ...extra,
  };
}

/**
 * @param {any} engine
 * @returns {string[]}
 */
function reasons(engine) {
  /** @type {string[]} */
  const found = [];
  engine.on('warning', (warning) => {
    if (warning.code === 'SUSPICIOUS_LEARNING' && POISON.includes(warning.reason)) {
      found.push(warning.reason);
    }
  });
  return found;
}

test('ramp fires when the last third of learning is more than 3× the first', () => {
  const engine = createEngine({ learnMs: 300, windowMs: 1, tiers: ['T0'] });
  const found = reasons(engine);
  for (let i = 0; i < 100; i += 1) {
    engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: i });
  }
  for (let i = 0; i < 100; i += 1) {
    engine.feed({ device: 'd', dst: 'a.example', bytes: 4, ts: 200 + i });
  }
  assert.deepStrictEqual(found, ['ramp']);
  assert.strictEqual(engine.stats().learningQuality.d.ready, false);
});

test('late-family-burst fires when most families appear in the last 10%', () => {
  const engine = createEngine({ learnMs: 1000, tiers: ['T0'] });
  const found = reasons(engine);
  engine.feed({ device: 'd', dst: '1.1.1.1', bytes: 1, ts: 0 });
  engine.feed({ device: 'd', dst: 'late-a.example', bytes: 1, ts: 900 });
  engine.feed({ device: 'd', dst: 'late-b.example', bytes: 1, ts: 950 });
  assert.deepStrictEqual(found, ['late-family-burst']);
  assert.strictEqual(engine.stats().learningQuality.d.ready, false);
});

test('the family-first cap drops a third late family before the burst can fire', () => {
  const engine = createEngine({ learnMs: 1000, tiers: ['T0'], maxDestinations: 2 });
  const found = reasons(engine);
  engine.feed({ device: 'd', dst: '1.1.1.1', bytes: 1, ts: 0 });
  engine.feed({ device: 'd', dst: 'early.example', bytes: 1, ts: 1 });
  engine.feed({ device: 'd', dst: 'late-a.example', bytes: 1, ts: 950 });
  engine.feed({ device: 'd', dst: 'late-b.example', bytes: 1, ts: 960 });
  assert.deepStrictEqual(found, []);
  assert.strictEqual(engine.stats().learningQuality.d.ready, true);
});

test('beacon-born-in-learning fires for a periodic destination after half of learning', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T0', 'T1'] });
  const found = reasons(engine);
  engine.feed({ device: 'd', dst: 'early.example', bytes: 1, ts: 0 });
  for (let i = 0; i < 20; i += 1) {
    engine.feed(flow({ ts: 6000 + i * 10, dstName: 'late.beacon.test', bytesOut: 100 }));
  }
  assert.deepStrictEqual(found, ['beacon-born-in-learning']);
  assert.strictEqual(engine.stats().learningQuality.d.ready, false);
});

test('the beacon track cap drops a periodic destination that arrives after 16 others', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T0', 'T1'] });
  const found = reasons(engine);
  engine.feed({ device: 'd', dst: 'early.example', bytes: 1, ts: 0 });
  for (let n = 0; n < 16; n += 1) {
    engine.feed(flow({ ts: 6000, dstName: `filler-${n}.example`, dstIp: '9.9.9.9' }));
  }
  for (let i = 0; i < 20; i += 1) {
    engine.feed(flow({ ts: 7000 + i * 10, dstName: 'late.beacon.test', bytesOut: 100 }));
  }
  assert.deepStrictEqual(found, []);
});

test('both benign matrices emit none of the new learning-poison reasons', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      for (const rich of [false, true]) {
        const events = simulate({
          profile,
          days: 14,
          seed,
          startTs: T0,
          rich,
          discovery: true,
          ipv6: true,
        });
        const engine = createEngine({
          learnMs: 7 * DAY,
          identity: 'auto',
          tiers: rich ? TIERS : ['T0'],
        });
        if (rich) engine.setDeviceClass(events[0].device, profile);
        /** @type {string[]} */
        const found = [];
        engine.on('warning', (warning) => {
          if (warning.code === 'SUSPICIOUS_LEARNING' && POISON.includes(warning.reason)) {
            found.push(warning.reason);
          }
        });
        for (const event of events) engine.feed(event);
        engine.flush(T0 + 14 * DAY);
        assert.deepStrictEqual(found, [], `${profile} seed ${seed} rich ${rich}`);
      }
    }
  }
});
