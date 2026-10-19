'use strict';

const { LruSet } = require('../engine/caps');
const { isBroadcast, isMulticast } = require('../engine/net');
const { assertState, readStrings, fillSet } = require('./state');

/**
 * A group send: 224.0.0.0/4, 255.255.255.255, or ff00::/8.
 * Not a peer, host, or listening port.
 * @param {unknown} ip
 * @returns {boolean}
 */
function isGroupDst(ip) {
  return typeof ip === 'string' && (isBroadcast(ip) || isMulticast(ip));
}

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

/** One empty LruSet, object plus Map, measured on Node 24. */
const EMPTY_LRU_BYTES = 240;

/**
 * @param {any} dev
 */
function memorySeen(dev) {
  return 32 + EMPTY_LRU_BYTES * 2 + (dev.seen.size + dev.fired.size) * 64;
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

/**
 * Numeric comparison. `margin` is `observed / threshold` when both are numbers.
 * @param {{ test: 'gt' | 'gte' | 'lt', observed: number | string, threshold: number, formula?: string, learned?: Record<string, number | string> }} spec
 */
function explainThreshold(spec) {
  /** @type {any} */
  const row = { test: spec.test, observed: spec.observed, threshold: spec.threshold };
  if (spec.formula != null) row.formula = spec.formula;
  if (spec.learned) row.learned = spec.learned;
  if (
    typeof spec.observed === 'number' &&
    typeof spec.threshold === 'number' &&
    spec.threshold !== 0
  ) {
    row.margin = spec.observed / spec.threshold;
  }
  return row;
}

/**
 * A value that was not in the learned set.
 * @param {{ observed: number | string, learnedCount: number, sample?: (number | string)[] }} spec
 */
function explainNewMember(spec) {
  const sample = Array.isArray(spec.sample) ? spec.sample.slice(0, 3) : [];
  return {
    test: 'new-member',
    observed: spec.observed,
    learned: { count: spec.learnedCount, sample: sample.join(',') },
  };
}

/**
 * A value that replaced another.
 * @param {{ observed: number | string, previous: number | string }} spec
 */
function explainChanged(spec) {
  return {
    test: 'changed',
    observed: spec.observed,
    learned: { previous: spec.previous },
  };
}

/**
 * An indicator, policy, path, or marker hit.
 * @param {{ observed: number | string, matched: number | string, source: string }} spec
 */
function explainMatch(spec) {
  return {
    test: 'match',
    observed: spec.observed,
    learned: { matched: spec.matched, source: spec.source },
  };
}

module.exports = {
  isGroupDst,
  seenState,
  exportSeen,
  importSeen,
  memorySeen,
  entropy,
  median,
  listed,
  explainThreshold,
  explainNewMember,
  explainChanged,
  explainMatch,
};
