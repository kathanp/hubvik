'use strict';

const { SampleRing } = require('../engine/caps');
const { assertSafeKeys } = require('../engine/validate');
const { emptyStats, pushSample } = require('../engine/math');

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

/**
 * A version-2 sample list, or a version-3 running summary.
 * @param {any} state
 * @param {number} cap
 * @param {string} id
 * @returns {{ count: number, mean: number, m2: number, max: number }}
 */
function readStreamState(state, cap, id) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new Error(`${id} state is invalid`);
  }
  assertSafeKeys(state, id);
  if (state.samples != null) {
    if (!Array.isArray(state.samples)) throw new Error('samples must be an array');
    if (state.samples.length > cap) throw new Error('array samples exceeds cap');
    const stats = emptyStats();
    for (const value of state.samples) {
      if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new Error('samples must be non-negative numbers');
      }
      pushSample(stats, value);
    }
    return stats;
  }
  if (!Number.isInteger(state.count) || state.count < 0) throw new Error(`${id} count is invalid`);
  for (const key of ['mean', 'm2', 'max']) {
    if (typeof state[key] !== 'number' || !Number.isFinite(state[key])) {
      throw new Error(`${id} ${key} is invalid`);
    }
  }
  if (state.max < 0) throw new Error(`${id} max is invalid`);
  return { count: state.count, mean: state.mean, m2: state.m2, max: state.max };
}

module.exports = { readSamples, readStreamState };
