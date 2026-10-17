'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');

/**
 * @param {any} caps
 */
function seenState(caps) {
  return { seen: new LruSet(caps.maxDestinations), fired: new LruSet(caps.maxAlertKeys) };
}

/**
 * @param {any} dev
 */
function exportSeen(dev) {
  return { seen: dev.seen.toArray(), fired: dev.fired.toArray() };
}

/**
 * @param {any} dev
 * @param {any} state
 * @param {any} caps
 * @param {string} id
 */
function importSeen(dev, state, caps, id) {
  assertState(state, id);
  dev.seen = fillSet(
    readStrings(state.seen, caps.maxDestinations, caps.maxString, 'seen'),
    caps.maxDestinations,
  );
  dev.fired = fillSet(
    readStrings(state.fired, caps.maxAlertKeys, caps.maxString, 'fired'),
    caps.maxAlertKeys,
  );
}

/**
 * @param {any} dev
 */
function memorySeen(dev) {
  return (dev.seen.size + dev.fired.size) * 32 + 16;
}

/**
 * Shannon entropy in bits per symbol.
 * @param {string} text
 * @returns {number}
 */
function entropy(text) {
  if (!text) return 0;
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const ch of text) counts.set(ch, (counts.get(ch) || 0) + 1);
  let value = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    value -= p * Math.log2(p);
  }
  return value;
}

/**
 * @param {number[]} values
 * @returns {number}
 */
function median(values) {
  if (values.length === 0) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1] + sorted[mid]) / 2;
  return sorted[mid];
}

/**
 * @param {string} name
 * @param {string[]} list
 * @returns {boolean}
 */
function listed(name, list) {
  if (!name) return false;
  const lower = name.toLowerCase();
  return list.some((item) => lower === item || lower.endsWith(`.${item}`));
}

module.exports = {
  seenState,
  exportSeen,
  importSeen,
  memorySeen,
  entropy,
  median,
  listed,
};
