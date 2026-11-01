'use strict';

const LISTS = require('../data/families.json');
const { weightOf } = require('./incidents');

/** @type {Map<string, string> | null} */
let cached = null;

/**
 * Detector id to family name. Built once from the D-130 lists.
 * @returns {Map<string, string>}
 */
function familyIndex() {
  if (cached) return cached;
  /** @type {Map<string, string>} */
  const index = new Map();
  for (const [name, ids] of Object.entries(LISTS)) {
    if (!Array.isArray(ids)) continue;
    for (const id of ids) index.set(id, name);
  }
  cached = index;
  return index;
}

const FAMILY_CAP = Object.keys(LISTS).length;

/**
 * Keep the alert when this anomaly is the heaviest in its family for this window.
 * The book lives on the alert state the engine already keeps, and it stops at the
 * family count. A hard rule always alerts. No family means no extra gate.
 * @param {{ family?: Map<string, { window: number, weight: number }> }} state
 * @param {any} anomaly
 * @param {number} windowMs
 * @returns {boolean}
 */
function allowFamilyAlert(state, anomaly, windowMs) {
  const family = anomaly.data && anomaly.data.family;
  if (!family || anomaly._partgHard === true) return true;
  if (!state.family) state.family = new Map();
  const book = state.family;
  const span = windowMs > 0 ? windowMs : 1;
  const window = Math.floor(anomaly.ts / span);
  const prev = book.get(family);
  const weight = weightOf(anomaly);
  if (prev && prev.window === window && weight <= prev.weight) return false;
  if (!prev && book.size >= FAMILY_CAP) return false;
  book.set(family, { window, weight });
  return true;
}

module.exports = { familyIndex, allowFamilyAlert, FAMILY_CAP };
