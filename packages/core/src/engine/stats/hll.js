'use strict';

const { assertSafeKeys } = require('../validate');
const { hash32, encodeTyped, decodeTyped } = require('./hash');

/**
 * HyperLogLog. `p` is the precision. The default is 10, so the register is 1,024 bytes.
 * @param {{ p?: number }} [opts]
 * @returns {{ p: number, registers: Uint8Array }}
 */
function createHll(opts = {}) {
  const p = opts.p == null ? 10 : opts.p;
  if (!Number.isInteger(p) || p < 4 || p > 16) throw new TypeError('hll.p is invalid');
  return { p, registers: new Uint8Array(1 << p) };
}

/**
 * @param {{ p: number, registers: Uint8Array }} sketch
 * @param {string | number} value
 * @returns {void}
 */
function add(sketch, value) {
  const data = typeof value === 'number' ? uintBytes(value) : value;
  const hash = hash32(data, 0x811c9dc5);
  const index = hash >>> (32 - sketch.p);
  const rest = hash & ((1 << (32 - sketch.p)) - 1);
  const rank = rho(rest, 32 - sketch.p);
  if (rank > sketch.registers[index]) sketch.registers[index] = rank;
}

/**
 * Register-wise maximum. Exact: each register equals max(left, right).
 * @param {{ p: number, registers: Uint8Array }} left
 * @param {{ p: number, registers: Uint8Array }} right
 * @returns {{ p: number, registers: Uint8Array }}
 */
function merge(left, right) {
  if (left.p !== right.p || left.registers.length !== right.registers.length) {
    throw new Error('hll precision mismatch');
  }
  const out = createHll({ p: left.p });
  for (let i = 0; i < out.registers.length; i++) {
    out.registers[i] = Math.max(left.registers[i], right.registers[i]);
  }
  return out;
}

/**
 * @param {{ p: number, registers: Uint8Array }} sketch
 * @returns {number}
 */
function count(sketch) {
  const m = sketch.registers.length;
  let sum = 0;
  let zeros = 0;
  for (let i = 0; i < m; i++) {
    sum += 2 ** -sketch.registers[i];
    if (sketch.registers[i] === 0) zeros += 1;
  }
  const estimate = (alpha(m) * m * m) / sum;
  if (estimate <= 2.5 * m && zeros > 0) return m * Math.log(m / zeros);
  if (estimate > 2 ** 32 / 30) return -(2 ** 32) * Math.log(1 - estimate / 2 ** 32);
  return estimate;
}

/**
 * @param {{ p: number, registers: Uint8Array }} sketch
 * @returns {{ p: number, registers: string }}
 */
function toJSON(sketch) {
  return { p: sketch.p, registers: encodeTyped(sketch.registers) };
}

/**
 * @param {unknown} raw
 * @returns {{ p: number, registers: Uint8Array }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('hll state must be an object');
  }
  assertSafeKeys(raw, 'hll');
  const row = /** @type {any} */ (raw);
  if (!Number.isInteger(row.p) || row.p < 4 || row.p > 16) throw new TypeError('hll.p is invalid');
  const registers = /** @type {Uint8Array} */ (
    decodeTyped(row.registers, 1 << row.p, Uint8Array, 'hll.registers')
  );
  return { p: row.p, registers };
}

/**
 * @param {number} m
 * @returns {number}
 */
function alpha(m) {
  if (m === 16) return 0.673;
  if (m === 32) return 0.697;
  if (m === 64) return 0.709;
  return 0.7213 / (1 + 1.079 / m);
}

/**
 * Leading-zero count of the low `bits`, plus one. A zero word ranks `bits + 1`.
 * @param {number} word
 * @param {number} bits
 * @returns {number}
 */
function rho(word, bits) {
  if (word === 0) return bits + 1;
  let rank = 1;
  for (let i = bits - 1; i >= 0; i--) {
    if ((word >>> i) & 1) return rank;
    rank += 1;
  }
  return bits + 1;
}

/**
 * @param {number} value
 * @returns {Uint8Array}
 */
function uintBytes(value) {
  const out = new Uint8Array(4);
  const n = value >>> 0;
  out[0] = n & 0xff;
  out[1] = (n >>> 8) & 0xff;
  out[2] = (n >>> 16) & 0xff;
  out[3] = (n >>> 24) & 0xff;
  return out;
}

module.exports = { createHll, add, merge, count, toJSON, fromJSON };
