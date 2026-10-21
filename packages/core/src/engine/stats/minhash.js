'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');
const { fnv1a32, fmix32, encodeTyped, decodeTyped } = require('./hash');

/**
 * MinHash signature. `k = 64` seeded `fmix32` permutations.
 * Jaccard is the fraction of equal slots. LSH banding is 16 bands of 4 rows.
 * The signature is a `Uint32Array(64)`, 256 bytes.
 */

const K = 64;
const BANDS = 16;
const ROWS = 4;
const EMPTY = 0xffffffff;

/**
 * Empty signature. Every slot is `0xFFFFFFFF` so the first token always wins the min.
 * @returns {{ sig: Uint32Array }}
 */
function createMinHash() {
  const sig = new Uint32Array(K);
  sig.fill(EMPTY);
  return { sig };
}

/**
 * Fold one token into the signature.
 * Slot `i` stores `min(sig[i], fmix32(fnv1a32(token, i + 1)))`.
 * @param {{ sig: Uint32Array }} state
 * @param {string} token
 * @returns {void}
 */
function add(state, token) {
  if (typeof token !== 'string') {
    throw new HubvikError('MINHASH_TOKEN_MUST_BE_A_STRING', 'minhash token must be a string');
  }
  const sig = state.sig;
  for (let i = 0; i < K; i++) {
    const hash = fmix32(fnv1a32(token, i + 1));
    if (hash < sig[i]) sig[i] = hash;
  }
}

/**
 * Jaccard estimate: the fraction of signature slots that are equal.
 * @param {{ sig: Uint32Array }} left
 * @param {{ sig: Uint32Array }} right
 * @returns {number}
 */
function jaccard(left, right) {
  let equal = 0;
  const a = left.sig;
  const b = right.sig;
  for (let i = 0; i < K; i++) {
    if (a[i] === b[i]) equal += 1;
  }
  return equal / K;
}

/**
 * LSH keys: 16 bands, each a copy of 4 consecutive uint32 rows.
 * @param {{ sig: Uint32Array }} state
 * @returns {Uint32Array[]}
 */
function bands(state) {
  /** @type {Uint32Array[]} */
  const out = new Array(BANDS);
  for (let band = 0; band < BANDS; band++) {
    const start = band * ROWS;
    out[band] = state.sig.slice(start, start + ROWS);
  }
  return out;
}

/**
 * @param {{ sig: Uint32Array }} state
 * @returns {{ sig: string }}
 */
function toJSON(state) {
  return { sig: encodeTyped(state.sig) };
}

/**
 * @param {unknown} raw
 * @returns {{ sig: Uint32Array }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('MINHASH_STATE_MUST_BE_AN_OBJECT', 'minhash state must be an object');
  }
  assertSafeKeys(raw, 'minhash');
  const sig = /** @type {Uint32Array} */ (
    decodeTyped(/** @type {any} */ (raw).sig, K, Uint32Array, 'minhash.sig')
  );
  return { sig };
}

module.exports = { createMinHash, add, jaccard, bands, toJSON, fromJSON };
