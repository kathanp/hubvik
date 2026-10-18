'use strict';

const { assertSafeKeys } = require('../validate');
const { hash32, encodeTyped, decodeTyped } = require('./hash');

/**
 * Count-Min sketch, width 256 and depth 4. This is LAN-wide scratch only.
 * Four kilobytes per device would break the memory budget, so never keep one per device.
 */

const WIDTH = 256;
const DEPTH = 4;

/**
 * @returns {{ table: Uint32Array }}
 */
function createCms() {
  return { table: new Uint32Array(WIDTH * DEPTH) };
}

/**
 * @param {{ table: Uint32Array }} sketch
 * @param {string} key
 * @returns {void}
 */
function add(sketch, key) {
  const slots = indexes(key);
  for (let row = 0; row < DEPTH; row++) sketch.table[row * WIDTH + slots[row]] += 1;
}

/**
 * @param {{ table: Uint32Array }} sketch
 * @param {string} key
 * @returns {number}
 */
function estimate(sketch, key) {
  const slots = indexes(key);
  let min = sketch.table[slots[0]];
  for (let row = 1; row < DEPTH; row++) {
    const value = sketch.table[row * WIDTH + slots[row]];
    if (value < min) min = value;
  }
  return min;
}

/**
 * @param {{ table: Uint32Array }} sketch
 * @returns {{ table: string }}
 */
function toJSON(sketch) {
  return { table: encodeTyped(sketch.table) };
}

/**
 * @param {unknown} raw
 * @returns {{ table: Uint32Array }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('cms state must be an object');
  }
  assertSafeKeys(raw, 'cms');
  const table = /** @type {Uint32Array} */ (
    decodeTyped(/** @type {any} */ (raw).table, WIDTH * DEPTH, Uint32Array, 'cms.table')
  );
  return { table };
}

/**
 * @param {string} key
 * @returns {number[]}
 */
function indexes(key) {
  /** @type {number[]} */
  const out = [];
  for (let row = 0; row < DEPTH; row++) out.push(hash32(key, 0x9e3779b9 + row) % WIDTH);
  return out;
}

module.exports = { createCms, add, estimate, toJSON, fromJSON, WIDTH, DEPTH };
