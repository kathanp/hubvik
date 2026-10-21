'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { mulberry32 } = require('../../../../test/fixtures/prng');
const { pushSample, emptyStats } = require('../../src/engine/math');
const welford = require('../../src/engine/stats/welford');
const ewma = require('../../src/engine/stats/ewma');
const p2 = require('../../src/engine/stats/p2');
const hll = require('../../src/engine/stats/hll');
const cms = require('../../src/engine/stats/cms');
const cusum = require('../../src/engine/stats/cusum');
const pagehinkley = require('../../src/engine/stats/pagehinkley');
const { fnv1a32, fmix32, hash32 } = require('../../src/engine/stats/hash');

/**
 * @param {number} left
 * @param {number} right
 * @returns {boolean}
 */
function close(left, right) {
  const scale = Math.max(Math.abs(left), Math.abs(right));
  if (scale === 0) return true;
  return Math.abs(left - right) / scale <= 1e-9;
}

/**
 * @param {() => number} rng
 * @returns {number}
 */
function normal(rng) {
  const u = Math.max(rng(), 1e-12);
  const v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

test('welford matches a two-pass and a Chan merge on 100,000 samples', () => {
  const rng = mulberry32(20261018);
  /** @type {number[]} */
  const values = [];
  const stats = welford.createWelford();
  const legacy = emptyStats();
  for (let i = 0; i < 100_000; i++) {
    const value = normal(rng);
    values.push(value);
    welford.push(stats, value);
    pushSample(legacy, value);
  }
  let sum = 0;
  let min = Infinity;
  let max = -Infinity;
  for (const value of values) {
    sum += value;
    if (value < min) min = value;
    if (value > max) max = value;
  }
  const mean = sum / values.length;
  let m2 = 0;
  for (const value of values) {
    const diff = value - mean;
    m2 += diff * diff;
  }
  assert.ok(close(stats.mean, mean));
  assert.ok(close(stats.m2, m2));
  assert.strictEqual(stats.count, values.length);
  assert.strictEqual(stats.min, min);
  assert.strictEqual(stats.max, max);
  assert.ok(close(stats.mean, legacy.mean));
  assert.ok(close(stats.m2, legacy.m2));
  assert.strictEqual(stats.max, legacy.max);

  const left = welford.createWelford();
  const right = welford.createWelford();
  for (let i = 0; i < 50_000; i++) welford.push(left, values[i]);
  for (let i = 50_000; i < values.length; i++) welford.push(right, values[i]);
  const joined = welford.merge(left, right);
  assert.ok(close(joined.mean, mean));
  assert.ok(close(joined.m2, m2));
  assert.strictEqual(joined.min, min);
  assert.strictEqual(joined.max, max);

  const saved = welford.toJSON(stats);
  assert.deepStrictEqual(welford.fromJSON(saved), {
    count: stats.count,
    mean: stats.mean,
    m2: stats.m2,
    min: stats.min,
    max: stats.max,
  });
  assert.throws(
    () => welford.fromJSON(JSON.parse('{"__proto__":{"x":1},"count":0,"mean":0,"m2":0}')),
    /forbidden key/,
  );
  assert.throws(() => welford.fromJSON({ count: 1, mean: 0, m2: -1, min: 0, max: 0 }), /m2/);
});

test('ewma mean and variance match the step-input closed form', () => {
  const alpha = 0.2;
  const n = 40;
  const stats = ewma.createEwma({ alpha });
  for (let i = 0; i < n; i++) ewma.push(stats, 1);
  const beta = 1 - alpha;
  assert.ok(close(stats.mean, 1 - beta ** n));
  assert.ok(close(stats.variance, beta ** (n + 1) * (1 - beta ** n)));
  const byHalf = ewma.createEwma({ halfLife: 1 });
  assert.ok(close(byHalf.alpha, 0.5));
  const saved = ewma.toJSON(stats);
  assert.deepStrictEqual(ewma.fromJSON(saved), saved);
  assert.throws(() => ewma.fromJSON({ alpha: 0, mean: 0, variance: 0, count: 0 }), /alpha/);
});

test('p2 p99 stays within 3% of the exact log-normal quantile', () => {
  const rng = mulberry32(20261018);
  const n = 10_000;
  const stats = p2.createP2(0.99);
  /** @type {number[]} */
  const values = [];
  for (let i = 0; i < n; i++) {
    const value = Math.exp(normal(rng));
    values.push(value);
    p2.push(stats, value);
  }
  values.sort((a, b) => a - b);
  const exact = values[Math.floor(0.99 * (n - 1))];
  const got = p2.quantile(stats);
  assert.ok(Math.abs(got - exact) / exact <= 0.03, `${got} vs ${exact}`);
  const again = p2.fromJSON(p2.toJSON(stats));
  assert.strictEqual(again.count, n);
  assert.ok(close(p2.quantile(again), got));
  assert.throws(() => p2.fromJSON({ p: 0.99, count: 1, markers: 'YQ==' }), /length/);
});

test('hyperloglog stays inside 3 × 1.04/sqrt(m) and merge is register-wise max', () => {
  const m = 1024;
  const limit = (3 * 1.04) / Math.sqrt(m);
  for (const distinct of [1e3, 1e4, 1e5, 1e6]) {
    const sketch = hll.createHll();
    for (let i = 0; i < distinct; i++) hll.add(sketch, i);
    const estimate = hll.count(sketch);
    const error = Math.abs(estimate - distinct) / distinct;
    assert.ok(error <= limit, `${distinct} error ${error}`);
  }
  const left = hll.createHll();
  const right = hll.createHll();
  const both = hll.createHll();
  for (let i = 0; i < 5000; i++) {
    hll.add(i % 2 === 0 ? left : right, i);
    hll.add(both, i);
  }
  const joined = hll.merge(left, right);
  assert.deepStrictEqual(Array.from(joined.registers), Array.from(both.registers));
  const restored = hll.fromJSON(hll.toJSON(both));
  assert.deepStrictEqual(Array.from(restored.registers), Array.from(both.registers));
  assert.throws(() => hll.fromJSON({ p: 10, registers: 'YQ==' }), /length/);
});

test('count-min overestimate stays within (e/256)·N on a seeded Zipf stream', () => {
  const rng = mulberry32(20261018);
  const n = 20_000;
  const universe = 300;
  let harmonic = 0;
  for (let k = 1; k <= universe; k++) harmonic += 1 / k;
  const sketch = cms.createCms();
  /** @type {Map<number, number>} */
  const truth = new Map();
  for (let i = 0; i < n; i++) {
    const target = rng() * harmonic;
    let acc = 0;
    let key = universe;
    for (let k = 1; k <= universe; k++) {
      acc += 1 / k;
      if (acc >= target) {
        key = k;
        break;
      }
    }
    const name = `k${key}`;
    cms.add(sketch, name);
    truth.set(key, (truth.get(key) || 0) + 1);
  }
  const allowance = (Math.E / cms.WIDTH) * n;
  for (const [key, seen] of truth) {
    const guessed = cms.estimate(sketch, `k${key}`);
    assert.ok(guessed >= seen);
    assert.ok(guessed - seen <= allowance, `${key} over by ${guessed - seen}`);
  }
  const restored = cms.fromJSON(cms.toJSON(sketch));
  assert.strictEqual(cms.estimate(restored, 'k1'), cms.estimate(sketch, 'k1'));
});

test('cusum and page-hinkley catch a seeded 1σ shift inside the documented bound', () => {
  const rng = mulberry32(7);
  const shift = cusum.createCusum({ k: 0.5, h: 5 });
  const drift = pagehinkley.createPageHinkley({ delta: 0.5, lambda: 8 });
  let cusumAt = -1;
  let pageAt = -1;
  for (let i = 0; i < 300; i++) {
    const value = normal(rng) + (i >= 100 ? 1 : 0);
    if (cusumAt < 0 && cusum.push(shift, value)) cusumAt = i;
    if (pageAt < 0 && pagehinkley.push(drift, value)) pageAt = i;
  }
  assert.ok(cusumAt >= 100 && cusumAt - 100 <= 40, `cusum at ${cusumAt}`);
  assert.ok(pageAt >= 100 && pageAt - 100 <= 60, `page-hinkley at ${pageAt}`);
  assert.deepStrictEqual(cusum.fromJSON(cusum.toJSON(shift)), shift);
  assert.deepStrictEqual(pagehinkley.fromJSON(pagehinkley.toJSON(drift)), drift);
});

test('streaming stats reject a bad options object and a bad snapshot', () => {
  assert.throws(() => cusum.createCusum(null), /object/);
  assert.throws(() => cusum.createCusum({ k: -1, h: 5 }), /cusum\.k/);
  assert.throws(() => cusum.createCusum({ k: 0.5, h: 0 }), /cusum\.h/);
  assert.throws(() => cusum.createCusum({ k: 0.5, h: 5, mean: Number.NaN }), /mean/);
  assert.throws(() => cusum.fromJSON(null), /object/);
  assert.throws(
    () => cusum.fromJSON({ k: 0.5, h: 5, mean: 0, high: -1, low: 0, alarmed: false }),
    /side/,
  );
  assert.throws(
    () => cusum.fromJSON({ k: 0.5, h: 5, mean: 0, high: 0, low: 0, alarmed: 1 }),
    /alarmed/,
  );
  assert.throws(() => ewma.createEwma(null), /object/);
  assert.throws(() => ewma.createEwma({ halfLife: 0 }), /halfLife/);
  assert.throws(() => ewma.createEwma({ alpha: 0 }), /alpha/);
  assert.throws(() => pagehinkley.createPageHinkley(null), /object/);
  assert.throws(() => pagehinkley.createPageHinkley({ delta: -1, lambda: 8 }), /delta/);
  assert.throws(() => pagehinkley.createPageHinkley({ delta: 0.5, lambda: 0 }), /lambda/);
  assert.throws(() => welford.fromJSON(null), /object/);
  assert.throws(() => welford.fromJSON({ count: 0, mean: 1, m2: 0 }), /empty/);
  assert.throws(() => welford.fromJSON({ count: 1, mean: 0, m2: -1, min: 0, max: 0 }), /m2/);
  assert.throws(() => welford.fromJSON({ count: 1, mean: 0, m2: 0, min: 2, max: 1 }), /min/);
  const empty = welford.fromJSON({ count: 0, mean: 0, m2: 0 });
  assert.strictEqual(empty.count, 0);
});

test('fnv-1a and fmix32 match fixed vectors', () => {
  assert.strictEqual(fnv1a32(''), 0x811c9dc5);
  assert.strictEqual(fnv1a32('a'), 0xe40c292c);
  assert.strictEqual(fnv1a32('foobar'), 0xbf9cf968);
  assert.strictEqual(fnv1a32('iotwarden'), 0xfc4cb3d2);
  assert.strictEqual(fmix32(0), 0);
  assert.strictEqual(fmix32(1), 0x514e28b7);
  assert.strictEqual(hash32(''), fmix32(0x811c9dc5));
  assert.strictEqual(hash32('', 1), 0x514e28b7);
  assert.strictEqual(hash32('a'), 0x1a80b1b3);
  assert.strictEqual(hash32('foobar'), 0x0c0da6dc);
  assert.strictEqual(hash32('iotwarden'), 0xafa41fad);
});
