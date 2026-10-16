'use strict';

const { SampleRing } = require('../engine/caps');
const { assertSafeKeys } = require('../engine/validate');

/**
 * @param {any} state
 * @param {{ maxWindows: number }} caps
 * @param {string} id
 */
function readSamples(state, caps, id) {
  if (!state || typeof state !== 'object' || Array.isArray(state))
    throw new Error(`${id} state is invalid`);
  assertSafeKeys(state, id);
  if (!Array.isArray(state.samples)) throw new Error('samples must be an array');
  if (state.samples.length > caps.maxWindows) throw new Error('array samples exceeds cap');
  const ring = new SampleRing(caps.maxWindows);
  for (const value of state.samples) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      throw new Error('samples must be non-negative numbers');
    }
    ring.push(value);
  }
  return ring;
}

module.exports = { readSamples };
