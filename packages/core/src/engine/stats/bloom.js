'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');
const { fnv1a32, fmix32 } = require('./hash');

/** 2^19 bits, stored as 65,536 bytes. */
const BITS = 1 << 19;
const BYTES = BITS >> 3;
const K = 4;

/**
 * Bloom filter. `m = 2^19` bits and `k = 4` Kirsch–Mitzenmacher positions.
 * @returns {{ bits: Uint8Array }}
 */
function createBloom() {
  return { bits: new Uint8Array(BYTES) };
}

/**
 * @param {string} token
 * @returns {number[]}
 */
function positions(token) {
  const h1 = fmix32(fnv1a32(token, 1));
  const h2 = fmix32(fnv1a32(token, 2)) | 1;
  /** @type {number[]} */
  const out = [];
  for (let i = 0; i < K; i += 1) out.push((h1 + i * h2) & (BITS - 1));
  return out;
}

/**
 * @param {{ bits: Uint8Array }} state
 * @returns {void}
 */
function assertBloom(state) {
  if (!state || typeof state !== 'object' || !(state.bits instanceof Uint8Array)) {
    throw new HubvikError('BLOOM_STATE_MUST_BE_AN_OBJECT', 'bloom state must be an object');
  }
  if (state.bits.length !== BYTES) {
    throw new HubvikError('BLOOM_STATE_MUST_BE_AN_OBJECT', 'bloom state must be an object');
  }
}

/**
 * Insert one family name.
 * @param {{ bits: Uint8Array }} state
 * @param {string} token
 * @returns {void}
 */
function add(state, token) {
  assertBloom(state);
  if (typeof token !== 'string' || token.length === 0) {
    throw new HubvikError('BLOOM_TOKEN_MUST_BE_A_STRING', 'bloom token must be a string');
  }
  const bits = state.bits;
  for (const index of positions(token)) bits[index >> 3] |= 1 << (index & 7);
}

/**
 * @param {{ bits: Uint8Array }} state
 * @param {string} token
 * @returns {boolean}
 */
function has(state, token) {
  assertBloom(state);
  if (typeof token !== 'string' || token.length === 0) {
    throw new HubvikError('BLOOM_TOKEN_MUST_BE_A_STRING', 'bloom token must be a string');
  }
  const bits = state.bits;
  for (const index of positions(token)) {
    if ((bits[index >> 3] & (1 << (index & 7))) === 0) return false;
  }
  return true;
}

/**
 * @param {{ bits: Uint8Array }} state
 * @returns {{ bits: string }}
 */
function toJSON(state) {
  assertBloom(state);
  return {
    bits: Buffer.from(state.bits.buffer, state.bits.byteOffset, state.bits.byteLength).toString(
      'base64',
    ),
  };
}

/**
 * @param {unknown} raw
 * @returns {{ bits: Uint8Array }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('BLOOM_STATE_MUST_BE_AN_OBJECT', 'bloom state must be an object');
  }
  assertSafeKeys(raw, 'bloom');
  const row = /** @type {any} */ (raw);
  if (typeof row.bits !== 'string') {
    throw new HubvikError('BLOOM_STATE_MUST_BE_AN_OBJECT', 'bloom state must be an object');
  }
  const bytes = Buffer.from(row.bits, 'base64');
  if (bytes.length !== BYTES) {
    throw new HubvikError('BLOOM_STATE_MUST_BE_AN_OBJECT', 'bloom state must be an object');
  }
  return { bits: Uint8Array.from(bytes) };
}

module.exports = { BITS, BYTES, K, createBloom, add, has, positions, toJSON, fromJSON };
