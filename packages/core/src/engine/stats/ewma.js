'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');

/**
 * EWMA mean and variance. `alpha` is the weight of the new sample.
 * A half-life of `h` samples sets `alpha` to `1 - 0.5 ** (1 / h)`.
 * Variance update, after the mean moves: `(1 - alpha) * var + alpha * (x - mean) ** 2`.
 * @param {{ alpha?: number, halfLife?: number }} opts
 * @returns {{ alpha: number, mean: number, variance: number, count: number }}
 */
function createEwma(opts) {
  if (!opts || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new HubvikError('EWMA_OPTIONS_MUST_BE_AN_OBJECT', 'ewma options must be an object');
  }
  assertSafeKeys(opts, 'ewma');
  let alpha = opts.alpha;
  if (opts.halfLife != null) {
    if (typeof opts.halfLife !== 'number' || !(opts.halfLife > 0)) {
      throw new HubvikError('EWMA_HALFLIFE_IS_INVALID', 'ewma.halfLife is invalid');
    }
    alpha = 1 - 0.5 ** (1 / opts.halfLife);
  }
  if (typeof alpha !== 'number' || !(alpha > 0) || alpha > 1) {
    throw new HubvikError('EWMA_ALPHA_IS_INVALID', 'ewma.alpha is invalid');
  }
  return { alpha, mean: 0, variance: 0, count: 0 };
}

/**
 * @param {{ alpha: number, mean: number, variance: number, count: number }} stats
 * @param {number} value
 * @returns {void}
 */
function push(stats, value) {
  stats.count += 1;
  const beta = 1 - stats.alpha;
  stats.mean += stats.alpha * (value - stats.mean);
  const err = value - stats.mean;
  stats.variance = beta * stats.variance + stats.alpha * err * err;
}

/**
 * @param {{ alpha: number, mean: number, variance: number, count: number }} stats
 * @returns {{ alpha: number, mean: number, variance: number, count: number }}
 */
function toJSON(stats) {
  return { alpha: stats.alpha, mean: stats.mean, variance: stats.variance, count: stats.count };
}

/**
 * @param {unknown} raw
 * @returns {{ alpha: number, mean: number, variance: number, count: number }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('EWMA_STATE_MUST_BE_AN_OBJECT', 'ewma state must be an object');
  }
  assertSafeKeys(raw, 'ewma');
  const row = /** @type {any} */ (raw);
  if (typeof row.alpha !== 'number' || !(row.alpha > 0) || row.alpha > 1) {
    throw new HubvikError('EWMA_ALPHA_IS_INVALID', 'ewma.alpha is invalid');
  }
  if (typeof row.mean !== 'number' || !Number.isFinite(row.mean)) {
    throw new HubvikError('EWMA_MEAN_IS_INVALID', 'ewma.mean is invalid');
  }
  if (typeof row.variance !== 'number' || !Number.isFinite(row.variance) || row.variance < 0) {
    throw new HubvikError('EWMA_VARIANCE_IS_INVALID', 'ewma.variance is invalid');
  }
  if (typeof row.count !== 'number' || !Number.isInteger(row.count) || row.count < 0) {
    throw new HubvikError('EWMA_COUNT_IS_INVALID', 'ewma.count is invalid');
  }
  return { alpha: row.alpha, mean: row.mean, variance: row.variance, count: row.count };
}

module.exports = { createEwma, push, toJSON, fromJSON };
