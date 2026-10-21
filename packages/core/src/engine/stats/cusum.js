'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');

/**
 * Two-sided Page CUSUM. `k` is the allowance and `h` is the decision limit.
 * Reference mean defaults to 0. An alarm stays set once either side passes `h`.
 * A seeded 1σ shift (k = 0.5, h = 5) is detected within 40 samples of the change.
 * @param {{ k: number, h: number, mean?: number }} opts
 * @returns {{ k: number, h: number, mean: number, high: number, low: number, alarmed: boolean }}
 */
function createCusum(opts) {
  if (!opts || typeof opts !== 'object')
    throw new HubvikError('CUSUM_OPTIONS_MUST_BE_AN_OBJECT', 'cusum options must be an object');
  assertSafeKeys(opts, 'cusum');
  if (typeof opts.k !== 'number' || !(opts.k >= 0) || !Number.isFinite(opts.k)) {
    throw new HubvikError('CUSUM_K_IS_INVALID', 'cusum.k is invalid');
  }
  if (typeof opts.h !== 'number' || !(opts.h > 0) || !Number.isFinite(opts.h)) {
    throw new HubvikError('CUSUM_H_IS_INVALID', 'cusum.h is invalid');
  }
  const mean = opts.mean == null ? 0 : opts.mean;
  if (typeof mean !== 'number' || !Number.isFinite(mean))
    throw new HubvikError('CUSUM_MEAN_IS_INVALID', 'cusum.mean is invalid');
  return { k: opts.k, h: opts.h, mean, high: 0, low: 0, alarmed: false };
}

/**
 * @param {{ k: number, h: number, mean: number, high: number, low: number, alarmed: boolean }} stats
 * @param {number} value
 * @returns {boolean}
 */
function push(stats, value) {
  const delta = value - stats.mean;
  stats.high = Math.max(0, stats.high + delta - stats.k);
  stats.low = Math.max(0, stats.low - delta - stats.k);
  if (stats.high > stats.h || stats.low > stats.h) stats.alarmed = true;
  return stats.alarmed;
}

/**
 * @param {{ k: number, h: number, mean: number, high: number, low: number, alarmed: boolean }} stats
 * @returns {{ k: number, h: number, mean: number, high: number, low: number, alarmed: boolean }}
 */
function toJSON(stats) {
  return {
    k: stats.k,
    h: stats.h,
    mean: stats.mean,
    high: stats.high,
    low: stats.low,
    alarmed: stats.alarmed,
  };
}

/**
 * @param {unknown} raw
 * @returns {{ k: number, h: number, mean: number, high: number, low: number, alarmed: boolean }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('CUSUM_STATE_MUST_BE_AN_OBJECT', 'cusum state must be an object');
  }
  assertSafeKeys(raw, 'cusum');
  const row = /** @type {any} */ (raw);
  const stats = createCusum({ k: row.k, h: row.h, mean: row.mean });
  stats.high = finite(row.high, 'cusum.high');
  stats.low = finite(row.low, 'cusum.low');
  if (stats.high < 0 || stats.low < 0)
    throw new HubvikError('CUSUM_SIDE_IS_INVALID', 'cusum side is invalid');
  if (typeof row.alarmed !== 'boolean')
    throw new HubvikError('CUSUM_ALARMED_IS_INVALID', 'cusum.alarmed is invalid');
  stats.alarmed = row.alarmed;
  return stats;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {number}
 */
function finite(value, label) {
  if (typeof value !== 'number' || !Number.isFinite(value))
    throw new HubvikError('IS_INVALID_2', `${label} is invalid`);
  return value;
}

module.exports = { createCusum, push, toJSON, fromJSON };
