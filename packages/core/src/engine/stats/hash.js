'use strict';

const { HubvikError } = require('../../errors');

const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

/**
 * FNV-1a 32. `seed` replaces the offset basis. No `Math.random` and no `crypto`.
 * @param {Uint8Array | string} data
 * @param {number} [seed]
 * @returns {number}
 */
function fnv1a32(data, seed = FNV_OFFSET) {
  const bytes = typeof data === 'string' ? Buffer.from(data) : data;
  let hash = seed >>> 0;
  for (let i = 0; i < bytes.length; i++) {
    hash ^= bytes[i];
    hash = Math.imul(hash, FNV_PRIME) >>> 0;
  }
  return hash;
}

/**
 * MurmurHash3 fmix32 finalizer.
 * @param {number} value
 * @returns {number}
 */
function fmix32(value) {
  let h = value >>> 0;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

/**
 * Seeded FNV-1a 32 followed by fmix32.
 * @param {Uint8Array | string} data
 * @param {number} [seed]
 * @returns {number}
 */
function hash32(data, seed = FNV_OFFSET) {
  return fmix32(fnv1a32(data, seed));
}

/**
 * @param {ArrayBufferView} view
 * @returns {string}
 */
function encodeTyped(view) {
  return Buffer.from(view.buffer, view.byteOffset, view.byteLength).toString('base64');
}

/**
 * @param {unknown} text
 * @param {number} length
 * @param {Uint8ArrayConstructor | Uint32ArrayConstructor | Float64ArrayConstructor} Type
 * @param {string} label
 * @returns {Uint8Array | Uint32Array | Float64Array}
 */
function decodeTyped(text, length, Type, label) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new HubvikError('MUST_BE_BASE64', `${label} must be base64`);
  }
  const bytes = Buffer.from(text, 'base64');
  const width = Type.BYTES_PER_ELEMENT;
  if (bytes.length !== length * width) {
    throw new HubvikError('LENGTH_MISMATCH', `${label} length mismatch`);
  }
  const out = new Type(length);
  new Uint8Array(out.buffer, out.byteOffset, out.byteLength).set(bytes);
  return out;
}

module.exports = { fnv1a32, fmix32, hash32, encodeTyped, decodeTyped, FNV_OFFSET, FNV_PRIME };
