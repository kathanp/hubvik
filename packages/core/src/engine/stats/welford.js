'use strict';

const { assertSafeKeys } = require('../validate');

/**
 * Running count, mean, M2, min, and max. The update matches `engine/math.js` `pushSample`
 * for count, mean, M2, and max. Min is extra and is not written into detector baselines.
 * @returns {{ count: number, mean: number, m2: number, min: number, max: number }}
 */
function createWelford() {
  return { count: 0, mean: 0, m2: 0, min: Infinity, max: -Infinity };
}

/**
 * @param {{ count: number, mean: number, m2: number, min: number, max: number }} stats
 * @param {number} value
 * @returns {void}
 */
function push(stats, value) {
  const count = stats.count + 1;
  const delta = value - stats.mean;
  const mean = stats.mean + delta / count;
  stats.m2 += delta * (value - mean);
  stats.mean = mean;
  stats.count = count;
  if (value < stats.min) stats.min = value;
  if (value > stats.max) stats.max = value;
}

/**
 * Chan's parallel merge. Does not mutate the inputs.
 * @param {{ count: number, mean: number, m2: number, min: number, max: number }} left
 * @param {{ count: number, mean: number, m2: number, min: number, max: number }} right
 * @returns {{ count: number, mean: number, m2: number, min: number, max: number }}
 */
function merge(left, right) {
  if (left.count === 0) return { ...right };
  if (right.count === 0) return { ...left };
  const count = left.count + right.count;
  const delta = right.mean - left.mean;
  return {
    count,
    mean: left.mean + (delta * right.count) / count,
    m2: left.m2 + right.m2 + (delta * delta * left.count * right.count) / count,
    min: Math.min(left.min, right.min),
    max: Math.max(left.max, right.max),
  };
}

/**
 * @param {{ count: number, mean: number, m2: number, min: number, max: number }} stats
 * @returns {{ count: number, mean: number, m2: number, min: number | null, max: number | null }}
 */
function toJSON(stats) {
  return {
    count: stats.count,
    mean: stats.mean,
    m2: stats.m2,
    min: stats.count === 0 ? null : stats.min,
    max: stats.count === 0 ? null : stats.max,
  };
}

/**
 * @param {unknown} raw
 * @returns {{ count: number, mean: number, m2: number, min: number, max: number }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('welford state must be an object');
  }
  assertSafeKeys(raw, 'welford');
  const count = integer(/** @type {any} */ (raw).count, 'welford.count');
  const mean = finite(/** @type {any} */ (raw).mean, 'welford.mean');
  const m2 = finite(/** @type {any} */ (raw).m2, 'welford.m2');
  if (m2 < 0) throw new Error('welford.m2 is invalid');
  if (count === 0) {
    if (mean !== 0 || m2 !== 0) throw new Error('welford empty state is invalid');
    return createWelford();
  }
  const min = finite(/** @type {any} */ (raw).min, 'welford.min');
  const max = finite(/** @type {any} */ (raw).max, 'welford.max');
  if (min > max) throw new Error('welford.min is above max');
  return { count, mean, m2, min, max };
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {number}
 */
function finite(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value))
    throw new TypeError(`${label} is invalid`);
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {number}
 */
function integer(value, label) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

module.exports = { createWelford, push, merge, toJSON, fromJSON };
