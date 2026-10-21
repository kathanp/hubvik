'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');
const { encodeTyped, decodeTyped } = require('./hash');

/**
 * P² streaming quantile (Jain and Chlamtac, 1985). Five markers in one Float64Array:
 * heights in 0..4 and positions in 5..9. The middle marker tracks `p`.
 * @param {number} p
 * @returns {{ p: number, count: number, markers: Float64Array, dn: Float64Array }}
 */
function createP2(p) {
  if (typeof p !== 'number' || !(p > 0) || !(p < 1))
    throw new HubvikError('P2_P_IS_INVALID', 'p2.p is invalid');
  return {
    p,
    count: 0,
    markers: new Float64Array(10),
    dn: new Float64Array([0, p / 2, p, (1 + p) / 2, 1]),
  };
}

/**
 * @param {{ p: number, count: number, markers: Float64Array, dn: Float64Array }} stats
 * @param {number} value
 * @returns {number}
 */
function push(stats, value) {
  const q = stats.markers.subarray(0, 5);
  const n = stats.markers.subarray(5, 10);
  if (stats.count < 5) {
    q[stats.count] = value;
    stats.count += 1;
    if (stats.count === 5) {
      const sorted = Array.from(q).sort((a, b) => a - b);
      for (let i = 0; i < 5; i++) {
        q[i] = sorted[i];
        n[i] = i + 1;
      }
    }
    return q[Math.min(2, stats.count - 1)];
  }
  stats.count += 1;
  let k;
  if (value < q[0]) {
    q[0] = value;
    k = 0;
  } else if (value >= q[4]) {
    q[4] = value;
    k = 3;
  } else {
    k = 0;
    while (k < 4 && value >= q[k + 1]) k += 1;
  }
  for (let i = k + 1; i < 5; i++) n[i] += 1;
  /** @type {number[]} */
  const desired = [0, 0, 0, 0, 0];
  for (let i = 0; i < 5; i++) desired[i] = 1 + (stats.count - 1) * stats.dn[i];
  for (let i = 1; i <= 3; i++) {
    const d = desired[i] - n[i];
    if ((d >= 1 && n[i + 1] - n[i] > 1) || (d <= -1 && n[i - 1] - n[i] < -1)) {
      const step = Math.sign(d);
      const parabolic = predict(q, n, i, step);
      if (q[i - 1] < parabolic && parabolic < q[i + 1]) q[i] = parabolic;
      else q[i] += (step * (q[i + step] - q[i])) / (n[i + step] - n[i]);
      n[i] += step;
    }
  }
  return q[2];
}

/**
 * @param {Float64Array} q
 * @param {Float64Array} n
 * @param {number} i
 * @param {number} step
 * @returns {number}
 */
function predict(q, n, i, step) {
  const span = n[i + 1] - n[i - 1];
  const left = (n[i] - n[i - 1] + step) * ((q[i + 1] - q[i]) / (n[i + 1] - n[i]));
  const right = (n[i + 1] - n[i] - step) * ((q[i] - q[i - 1]) / (n[i] - n[i - 1]));
  return q[i] + (step / span) * (left + right);
}

/**
 * @param {{ p: number, count: number, markers: Float64Array }} stats
 * @returns {number}
 */
function quantile(stats) {
  return stats.markers[Math.min(2, Math.max(0, stats.count - 1))];
}

/**
 * @param {{ p: number, count: number, markers: Float64Array }} stats
 * @returns {{ p: number, count: number, markers: string }}
 */
function toJSON(stats) {
  return { p: stats.p, count: stats.count, markers: encodeTyped(stats.markers) };
}

/**
 * @param {unknown} raw
 * @returns {{ p: number, count: number, markers: Float64Array, dn: Float64Array }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('P2_STATE_MUST_BE_AN_OBJECT', 'p2 state must be an object');
  }
  assertSafeKeys(raw, 'p2');
  const row = /** @type {any} */ (raw);
  if (typeof row.p !== 'number' || !(row.p > 0) || !(row.p < 1))
    throw new HubvikError('P2_P_IS_INVALID', 'p2.p is invalid');
  if (typeof row.count !== 'number' || !Number.isInteger(row.count) || row.count < 0) {
    throw new HubvikError('P2_COUNT_IS_INVALID', 'p2.count is invalid');
  }
  const markers = /** @type {Float64Array} */ (
    decodeTyped(row.markers, 10, Float64Array, 'p2.markers')
  );
  for (let i = 0; i < markers.length; i++) {
    if (!Number.isFinite(markers[i]))
      throw new HubvikError('P2_MARKERS_IS_INVALID', 'p2.markers is invalid');
  }
  return {
    p: row.p,
    count: row.count,
    markers,
    dn: new Float64Array([0, row.p / 2, row.p, (1 + row.p) / 2, 1]),
  };
}

module.exports = { createP2, push, quantile, toJSON, fromJSON };
