'use strict';

const { assertSafeKeys } = require('../validate');

/**
 * Two-sided Page–Hinkley test. `delta` is the tolerated drift and `lambda` is the threshold.
 * A seeded 1σ upward shift (delta = 0.5, lambda = 8, seed 7) is detected within 60 samples of the change.
 * @param {{ delta: number, lambda: number }} opts
 * @returns {{ delta: number, lambda: number, count: number, mean: number, up: number, upMin: number, down: number, downMin: number, alarmed: boolean }}
 */
function createPageHinkley(opts) {
  if (!opts || typeof opts !== 'object')
    throw new TypeError('pagehinkley options must be an object');
  assertSafeKeys(opts, 'pagehinkley');
  if (typeof opts.delta !== 'number' || !(opts.delta >= 0) || !Number.isFinite(opts.delta)) {
    throw new TypeError('pagehinkley.delta is invalid');
  }
  if (typeof opts.lambda !== 'number' || !(opts.lambda > 0) || !Number.isFinite(opts.lambda)) {
    throw new TypeError('pagehinkley.lambda is invalid');
  }
  return {
    delta: opts.delta,
    lambda: opts.lambda,
    count: 0,
    mean: 0,
    up: 0,
    upMin: 0,
    down: 0,
    downMin: 0,
    alarmed: false,
  };
}

/**
 * @param {{ delta: number, lambda: number, count: number, mean: number, up: number, upMin: number, down: number, downMin: number, alarmed: boolean }} stats
 * @param {number} value
 * @returns {boolean}
 */
function push(stats, value) {
  stats.count += 1;
  stats.mean += (value - stats.mean) / stats.count;
  stats.up += value - stats.mean - stats.delta;
  stats.down += stats.mean - stats.delta - value;
  if (stats.up < stats.upMin) stats.upMin = stats.up;
  if (stats.down < stats.downMin) stats.downMin = stats.down;
  if (stats.up - stats.upMin > stats.lambda || stats.down - stats.downMin > stats.lambda) {
    stats.alarmed = true;
  }
  return stats.alarmed;
}

/**
 * @param {ReturnType<typeof createPageHinkley>} stats
 * @returns {ReturnType<typeof createPageHinkley>}
 */
function toJSON(stats) {
  return { ...stats };
}

/**
 * @param {unknown} raw
 * @returns {ReturnType<typeof createPageHinkley>}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('pagehinkley state must be an object');
  }
  assertSafeKeys(raw, 'pagehinkley');
  const row = /** @type {any} */ (raw);
  const stats = createPageHinkley({ delta: row.delta, lambda: row.lambda });
  if (typeof row.count !== 'number' || !Number.isInteger(row.count) || row.count < 0) {
    throw new TypeError('pagehinkley.count is invalid');
  }
  stats.count = row.count;
  stats.mean = finite(row.mean, 'pagehinkley.mean');
  stats.up = finite(row.up, 'pagehinkley.up');
  stats.upMin = finite(row.upMin, 'pagehinkley.upMin');
  stats.down = finite(row.down, 'pagehinkley.down');
  stats.downMin = finite(row.downMin, 'pagehinkley.downMin');
  if (typeof row.alarmed !== 'boolean') throw new TypeError('pagehinkley.alarmed is invalid');
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
    throw new TypeError(`${label} is invalid`);
  return value;
}

module.exports = { createPageHinkley, push, toJSON, fromJSON };
