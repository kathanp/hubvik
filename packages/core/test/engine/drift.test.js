'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { HubvikError } = require('../../src/errors');
const { createWelford, push } = require('../../src/engine/stats/welford');
const { SERIES, createDrift, observe, toJSON, fromJSON } = require('../../src/engine/drift');

/** Days 0–7. From day 8 the step test multiplies each value by 3. */
const BASE = [10, 12, 9, 11, 10, 13, 8, 11];

/**
 * Population σ from the learning week, `sqrt(m2 / count)`.
 * @param {number[]} values
 * @returns {number}
 */
function learnedSigma(values) {
  const stats = createWelford();
  for (const value of values) push(stats, value);
  return Math.sqrt(stats.m2 / stats.count);
}

test('series names are families, bytesOut, ports, and hours', () => {
  assert.deepStrictEqual(SERIES, ['families', 'bytesOut', 'ports', 'hours']);
});

test('a step of value × 3 from day 8 crosses upward within 3 days', () => {
  const sigma = learnedSigma(BASE);
  const state = createDrift('cam');
  /** @type {{ series: string, direction: string } | null} */
  let hit = null;
  let hitDay = -1;
  for (let day = 0; day < 16; day++) {
    const value = day < 8 ? BASE[day] : BASE[day - 8] * 3;
    const got = observe(state, 'families', value, day, sigma);
    if (!got) continue;
    assert.strictEqual(hit, null);
    hit = got;
    hitDay = day;
  }
  assert.ok(hit);
  assert.deepStrictEqual(hit, { series: 'families', direction: 'up' });
  assert.ok(hitDay >= 8 && hitDay <= 10, `crossed on day ${hitDay}`);
  const saved = toJSON(state);
  assert.strictEqual(saved.families.count, 16);
  assert.strictEqual(saved.families.page.count, 15 - hitDay);
  assert.strictEqual(saved.families.page.alarmed, false);
  assert.strictEqual(saved.ports.count, 0);
  assert.strictEqual(saved.bytesOut.count, 0);
  assert.strictEqual(saved.hours.count, 0);
});

test('14 quiet days emit at most one crossing', () => {
  const sigma = learnedSigma(BASE);
  const state = createDrift('cam');
  let hits = 0;
  for (let day = 0; day < 14; day++) {
    const got = observe(state, 'bytesOut', BASE[day % BASE.length], day, sigma);
    if (got) hits += 1;
  }
  assert.ok(hits <= 1);
});

test('a downward step reports direction down once', () => {
  const sigma = learnedSigma(BASE);
  const state = createDrift('cam');
  /** @type {{ series: string, direction: string } | null} */
  let hit = null;
  let hitDay = -1;
  let hits = 0;
  for (let day = 0; day < 16; day++) {
    const value = day < 8 ? BASE[day] : BASE[day % 8] / 3;
    const got = observe(state, 'ports', value, day, sigma);
    if (!got) continue;
    hits += 1;
    if (!hit) {
      hit = got;
      hitDay = day;
    }
  }
  assert.ok(hit);
  assert.deepStrictEqual(hit, { series: 'ports', direction: 'down' });
  assert.ok(hitDay >= 8 && hitDay <= 12);
  assert.strictEqual(hits, 1);
});

test('sigma 0 does not report drift', () => {
  const state = createDrift('cam');
  for (let day = 0; day < 10; day++) {
    const value = day < 8 ? 10 : 30;
    assert.strictEqual(observe(state, 'hours', value, day, 0), null);
  }
  assert.strictEqual(toJSON(state).hours.count, 10);
});

test('round-trip keeps the page-hinkley state through the crossing', () => {
  const sigma = learnedSigma(BASE);
  const live = createDrift('cam');
  for (let day = 0; day < 8; day++) {
    assert.strictEqual(observe(live, 'ports', BASE[day], day, sigma), null);
  }
  const raw = JSON.parse(JSON.stringify(toJSON(live)));
  const copy = fromJSON(raw);
  assert.deepStrictEqual(toJSON(copy), toJSON(live));
  const left = observe(live, 'ports', BASE[0] * 3, 8, sigma);
  const right = observe(copy, 'ports', BASE[0] * 3, 8, sigma);
  assert.deepStrictEqual(left, { series: 'ports', direction: 'up' });
  assert.deepStrictEqual(right, left);
});

test('bad drift input does not change state', () => {
  const state = createDrift('cam');
  observe(state, 'families', 1, 0, 1);
  const before = structuredClone(toJSON(state));
  assert.throws(
    () => observe(state, 'Families', 1, 1, 1),
    (err) => {
      assert.ok(err instanceof HubvikError);
      assert.strictEqual(err.code, 'DRIFT_SERIES_IS_INVALID');
      return true;
    },
  );
  assert.throws(
    () => observe(state, 'families', 1, 0, 1),
    (err) => {
      assert.ok(err instanceof HubvikError);
      assert.strictEqual(err.code, 'DRIFT_DAY_IS_INVALID');
      return true;
    },
  );
  assert.throws(() => observe(state, 'families', Number.NaN, 1, 1), /drift value/);
  assert.throws(() => observe(state, 'families', 1, 1, -1), /drift sigma/);
  assert.throws(() => createDrift(''), /drift device/);
  assert.throws(() => createDrift('__proto__'), /drift device/);
  assert.throws(
    () => fromJSON(JSON.parse('{"__proto__":{"x":1},"deviceId":"cam"}')),
    /forbidden key/,
  );
  assert.deepStrictEqual(toJSON(state), before);
});
