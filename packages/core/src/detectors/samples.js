'use strict';

const { HubvikError } = require('../errors');

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
    throw new HubvikError('STATE_IS_INVALID', `${id} state is invalid`);
  assertSafeKeys(state, id);
  if (!Array.isArray(state.samples))
    throw new HubvikError('SAMPLES_MUST_BE_AN_ARRAY', 'samples must be an array');
  if (state.samples.length > caps.maxWindows)
    throw new HubvikError('ARRAY_SAMPLES_EXCEEDS_CAP', 'array samples exceeds cap');
  const ring = new SampleRing(caps.maxWindows);
  for (const value of state.samples) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      throw new HubvikError(
        'SAMPLES_MUST_BE_NON_NEGATIVE_NUMBERS',
        'samples must be non-negative numbers',
      );
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
    throw new HubvikError('STATE_IS_INVALID', `${id} state is invalid`);
  }
  assertSafeKeys(state, id);
  if (state.samples != null) {
    if (!Array.isArray(state.samples))
      throw new HubvikError('SAMPLES_MUST_BE_AN_ARRAY', 'samples must be an array');
    if (state.samples.length > cap)
      throw new HubvikError('ARRAY_SAMPLES_EXCEEDS_CAP', 'array samples exceeds cap');
    const stats = emptyStats();
    for (const value of state.samples) {
      if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new HubvikError(
          'SAMPLES_MUST_BE_NON_NEGATIVE_NUMBERS',
          'samples must be non-negative numbers',
        );
      }
      pushSample(stats, value);
    }
    return stats;
  }
  if (!Number.isInteger(state.count) || state.count < 0)
    throw new HubvikError('COUNT_IS_INVALID', `${id} count is invalid`);
  for (const key of ['mean', 'm2', 'max']) {
    if (typeof state[key] !== 'number' || !Number.isFinite(state[key])) {
      throw new HubvikError('IS_INVALID', `${id} ${key} is invalid`);
    }
  }
  if (state.max < 0) throw new HubvikError('MAX_IS_INVALID', `${id} max is invalid`);
  return { count: state.count, mean: state.mean, m2: state.m2, max: state.max };
}

module.exports = { readSamples, readStreamState };
