'use strict';

const { readFileSync } = require('node:fs');

const TYPES = new Set([
  'ip',
  'cidr',
  'domain',
  'ja4',
  'tor',
  'ad',
  'tracker',
  'proxy-sdk',
  'young-domain',
]);
const NAME_TYPES = new Set(['domain', 'tor', 'ad', 'tracker', 'proxy-sdk', 'young-domain']);
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const DEFAULT_MAX = 100_000;

/**
 * Turn text the host already has into the array `loadIndicators()` accepts.
 * This function does not fetch a feed and does not ship indicator rows.
 * @param {string} text JSON array, JSON lines, or `type value [source]` lines.
 * @param {{ source?: string, expiresTs?: number, max?: number }} [opts]
 * @returns {{ value: string, type: string, source: string, confidence: number, expiresTs: number | null }[]}
 */
function parseIndicators(text, opts = {}) {
  if (typeof text !== 'string') throw new TypeError('indicator file is invalid');
  const max = opts.max == null ? DEFAULT_MAX : opts.max;
  if (!Number.isInteger(max) || max < 1) throw new TypeError('indicator cap is invalid');
  const source = opts.source == null ? 'file' : opts.source;
  if (typeof source !== 'string' || source.length === 0 || source.length > 255) {
    throw new TypeError('indicator source is invalid');
  }
  if (
    opts.expiresTs != null &&
    (typeof opts.expiresTs !== 'number' || !Number.isFinite(opts.expiresTs))
  ) {
    throw new TypeError('indicator expiresTs is invalid');
  }
  const trimmed = text.trim();
  if (!trimmed) return [];
  const rows = trimmed.startsWith('[')
    ? fromJson(trimmed, source, opts.expiresTs)
    : fromLines(text, source, opts.expiresTs);
  if (rows.length > max) throw new TypeError('indicator file exceeds cap');
  return rows;
}

/**
 * Read a file the host downloaded. No network call.
 * @param {string} file
 * @param {{ source?: string, expiresTs?: number, max?: number }} [opts]
 */
function loadIndicatorFile(file, opts) {
  if (typeof file !== 'string' || file.length === 0)
    throw new TypeError('indicator file is invalid');
  return parseIndicators(readFileSync(file, 'utf8'), opts);
}

/**
 * @param {string} text
 * @param {string} source
 * @param {number | undefined} expiresTs
 */
function fromJson(text, source, expiresTs) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError('indicator file is invalid');
  }
  if (!Array.isArray(parsed)) throw new TypeError('indicator file is invalid');
  return parsed.map((row) => indicatorFrom(row, source, expiresTs));
}

/**
 * @param {string} text
 * @param {string} source
 * @param {number | undefined} expiresTs
 */
function fromLines(text, source, expiresTs) {
  /** @type {ReturnType<typeof indicatorFrom>[]} */
  const rows = [];
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    if (line.startsWith('{')) {
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        throw new TypeError('indicator file is invalid');
      }
      rows.push(indicatorFrom(parsed, source, expiresTs));
      continue;
    }
    const parts = line.split(/\s+/);
    if (parts.length < 2 || parts.length > 3) throw new TypeError('indicator file is invalid');
    rows.push(
      indicatorFrom({ type: parts[0], value: parts[1], source: parts[2] }, source, expiresTs),
    );
  }
  return rows;
}

/**
 * @param {any} raw
 * @param {string} fallbackSource
 * @param {number | undefined} fallbackExpiry
 */
function indicatorFrom(raw, fallbackSource, fallbackExpiry) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('indicator must be an object');
  }
  for (const key of Object.keys(raw)) {
    if (FORBIDDEN.has(key)) throw new TypeError('indicator is invalid');
  }
  if (typeof raw.value !== 'string' || raw.value.length === 0 || raw.value.length > 255) {
    throw new TypeError('indicator value is invalid');
  }
  if (!TYPES.has(raw.type)) throw new TypeError('indicator type is invalid');
  const source = raw.source == null ? fallbackSource : raw.source;
  if (typeof source !== 'string' || source.length === 0 || source.length > 255) {
    throw new TypeError('indicator source is invalid');
  }
  const confidence = raw.confidence == null ? 1 : raw.confidence;
  if (
    typeof confidence !== 'number' ||
    !Number.isFinite(confidence) ||
    confidence < 0 ||
    confidence > 1
  ) {
    throw new TypeError('indicator confidence is invalid');
  }
  let expiresTs = null;
  if (raw.expiresTs != null) {
    if (typeof raw.expiresTs !== 'number' || !Number.isFinite(raw.expiresTs)) {
      throw new TypeError('indicator expiresTs is invalid');
    }
    expiresTs = raw.expiresTs;
  } else if (fallbackExpiry != null) {
    expiresTs = fallbackExpiry;
  }
  const value = NAME_TYPES.has(raw.type) ? raw.value.toLowerCase() : raw.value;
  return { value, type: raw.type, source, confidence, expiresTs };
}

module.exports = { parseIndicators, loadIndicatorFile };
