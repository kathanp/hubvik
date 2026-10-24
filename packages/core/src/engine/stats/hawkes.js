'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');

/** SPEC H2. Times are event timestamps in milliseconds. */
const CAP = 32;
const HALF_LIFE_MS = 600000;
const MU = 0.02;
const ALPHA = 0.8;
const THRESHOLD = 3;
const DECAY = Math.LN2 / HALF_LIFE_MS;

/**
 * Bounded exponential Hawkes intensity. The ring keeps the newest `CAP` times.
 * @returns {{ times: number[] }}
 */
function createHawkes() {
  return { times: [] };
}

/**
 * Intensity from events already stored, at `ts`. The call does not record `ts`.
 * @param {{ times: number[] }} state
 * @param {number} ts
 * @returns {number}
 */
function intensity(state, ts) {
  let sum = 0;
  for (const time of state.times) {
    const age = ts - time;
    if (age >= 0) sum += Math.exp(-DECAY * age);
  }
  return MU + ALPHA * sum;
}

/**
 * True when the past intensity has reached the H2 threshold.
 * @param {{ times: number[] }} state
 * @param {number} ts
 * @returns {boolean}
 */
function excited(state, ts) {
  return intensity(state, ts) >= THRESHOLD;
}

/**
 * Record one excitation time. Drops the oldest time past the cap.
 * @param {{ times: number[] }} state
 * @param {number} ts
 * @returns {void}
 */
function observe(state, ts) {
  state.times.push(ts);
  if (state.times.length > CAP) state.times.shift();
}

/**
 * @param {{ times: number[] }} state
 * @returns {{ times: number[] }}
 */
function toJSON(state) {
  return { times: state.times.slice() };
}

/**
 * @param {unknown} raw
 * @returns {{ times: number[] }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('HAWKES_STATE_IS_INVALID', 'hawkes state is invalid');
  }
  assertSafeKeys(raw, 'hawkes');
  const times = /** @type {any} */ (raw).times;
  if (!Array.isArray(times) || times.length > CAP) {
    throw new HubvikError('HAWKES_STATE_IS_INVALID', 'hawkes state is invalid');
  }
  /** @type {number[]} */
  const copy = [];
  for (const time of times) {
    if (!Number.isFinite(time)) {
      throw new HubvikError('HAWKES_STATE_IS_INVALID', 'hawkes state is invalid');
    }
    copy.push(time);
  }
  return { times: copy };
}

module.exports = {
  ALPHA,
  CAP,
  HALF_LIFE_MS,
  MU,
  THRESHOLD,
  createHawkes,
  excited,
  fromJSON,
  intensity,
  observe,
  toJSON,
};
