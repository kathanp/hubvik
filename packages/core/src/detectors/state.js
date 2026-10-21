'use strict';

const { HubvikError } = require('../errors');

const { LruSet } = require('../engine/caps');
const { assertSafeKeys } = require('../engine/validate');

/**
 * @param {any} state
 * @param {string} id
 */
function assertState(state, id) {
  if (!state || typeof state !== 'object' || Array.isArray(state))
    throw new HubvikError('STATE_IS_INVALID', `${id} state is invalid`);
  assertSafeKeys(state, id);
}

/**
 * @param {unknown} value
 * @param {number} max
 * @param {number} maxString
 * @param {string} label
 * @returns {string[]}
 */
function readStrings(value, max, maxString, label) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new HubvikError('MUST_BE_AN_ARRAY', `${label} must be an array`);
  if (value.length > max) throw new HubvikError('ARRAY_EXCEEDS_CAP', `array ${label} exceeds cap`);
  for (const item of value) {
    if (typeof item !== 'string')
      throw new HubvikError('MUST_BE_STRINGS', `${label} must be strings`);
    if (item.length > maxString) throw new HubvikError('STRING_TOO_LONG', 'string too long');
  }
  return itemList(value);
}

/**
 * @param {any[]} value
 * @returns {string[]}
 */
function itemList(value) {
  return value;
}

/**
 * @param {string[]} values
 * @param {number} max
 * @returns {any}
 */
function fillSet(values, max) {
  const set = new LruSet(max);
  for (const value of values) set.add(value);
  return set;
}

module.exports = { assertState, readStrings, fillSet };
