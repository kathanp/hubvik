'use strict';

const { readFileSync } = require('node:fs');

const BAD_KEYS = new Set(['regex', 'regexp', 'pcre', '__proto__', 'constructor', 'prototype']);
const DEFAULT_MAX = 256;

/**
 * Read site rules the host already stored as JSON.
 * A key named regex, regexp, or pcre is rejected. `loadRules()` still validates the rows.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {object[]}
 */
function parseRules(text, opts = {}) {
  if (typeof text !== 'string') throw new TypeError('rules file is invalid');
  const max = opts.max == null ? DEFAULT_MAX : opts.max;
  if (!Number.isInteger(max) || max < 1) throw new TypeError('rules cap is invalid');
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError('rules file is invalid');
  }
  if (!Array.isArray(parsed)) throw new TypeError('rules file is invalid');
  if (parsed.length > max) throw new TypeError('rules file exceeds cap');
  walk(parsed);
  return parsed;
}

/**
 * Read a rules file the host stored. No network call.
 * @param {string} file
 * @param {{ max?: number }} [opts]
 */
function loadRulesFile(file, opts) {
  if (typeof file !== 'string' || file.length === 0) throw new TypeError('rules file is invalid');
  return parseRules(readFileSync(file, 'utf8'), opts);
}

/**
 * @param {unknown} value
 */
function walk(value) {
  if (!value || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (const item of value) walk(item);
    return;
  }
  for (const key of Object.keys(value)) {
    if (BAD_KEYS.has(key)) throw new TypeError('rules file is invalid');
    walk(/** @type {Record<string, unknown>} */ (value)[key]);
  }
}

module.exports = { parseRules, loadRulesFile };
