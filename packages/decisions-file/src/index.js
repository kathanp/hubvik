'use strict';

const { readFileSync } = require('node:fs');

const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const DEFAULT_MAX = 100_000;
const DAY = 86_400_000;

/**
 * Turn decisions the host already downloaded into indicator rows.
 * A decision type such as ban is ignored. Nothing is blocked.
 * @param {string} text JSON array or JSON lines.
 * @param {{ now?: number, source?: string, max?: number }} [opts]
 * @returns {{ value: string, type: string, source: string, confidence: number, expiresTs: number | null }[]}
 */
function parseDecisions(text, opts = {}) {
  if (typeof text !== 'string') throw new TypeError('decisions file is invalid');
  const max = opts.max == null ? DEFAULT_MAX : opts.max;
  if (!Number.isInteger(max) || max < 1) throw new TypeError('decisions cap is invalid');
  const source = opts.source == null ? 'decisions' : opts.source;
  if (typeof source !== 'string' || source.length === 0 || source.length > 255) {
    throw new TypeError('decisions source is invalid');
  }
  const trimmed = text.trim();
  if (!trimmed) return [];
  const raw = trimmed.startsWith('[') ? fromJson(trimmed) : fromLines(text);
  if (raw.length > max) throw new TypeError('decisions file exceeds cap');
  return raw.map((row) => decisionFrom(row, opts.now, source));
}

/**
 * Read a decisions file the host downloaded. No network call.
 * @param {string} file
 * @param {{ now?: number, source?: string, max?: number }} [opts]
 */
function loadDecisionsFile(file, opts) {
  if (typeof file !== 'string' || file.length === 0)
    throw new TypeError('decisions file is invalid');
  return parseDecisions(readFileSync(file, 'utf8'), opts);
}

/**
 * @param {string} text
 */
function fromJson(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError('decisions file is invalid');
  }
  if (!Array.isArray(parsed)) throw new TypeError('decisions file is invalid');
  return parsed;
}

/**
 * @param {string} text
 */
function fromLines(text) {
  /** @type {any[]} */
  const rows = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    try {
      rows.push(JSON.parse(trimmed));
    } catch {
      throw new TypeError('decisions file is invalid');
    }
  }
  return rows;
}

/**
 * @param {any} raw
 * @param {number | undefined} now
 * @param {string} fallback
 */
function decisionFrom(raw, now, fallback) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new TypeError('decision is invalid');
  for (const key of Object.keys(raw)) {
    if (FORBIDDEN.has(key)) throw new TypeError('decision is invalid');
  }
  if (typeof raw.value !== 'string' || raw.value.length === 0 || raw.value.length > 255) {
    throw new TypeError('decision value is invalid');
  }
  const type = indicatorType(raw.scope, raw.value);
  const value = type === 'domain' ? raw.value.toLowerCase() : raw.value;
  const scenario = raw.scenario == null ? fallback : raw.scenario;
  if (typeof scenario !== 'string' || scenario.length === 0 || scenario.length > 255) {
    throw new TypeError('decision scenario is invalid');
  }
  let expiresTs = null;
  if (raw.duration != null) {
    if (typeof now !== 'number' || !Number.isFinite(now))
      throw new TypeError('decision now is invalid');
    expiresTs = now + durationMs(raw.duration);
  }
  return { value, type, source: scenario, confidence: 1, expiresTs };
}

/**
 * Ip, Range, and domain scopes become indicator types. The ban field is not copied.
 * @param {unknown} scope
 * @param {string} value
 */
function indicatorType(scope, value) {
  const name = typeof scope === 'string' ? scope.toLowerCase() : '';
  if (name === 'range' || value.includes('/')) {
    if (!isCidr(value)) throw new TypeError('decision value is invalid');
    return 'cidr';
  }
  if (name === 'domain' || name === 'fqdn') {
    if (!isDomain(value)) throw new TypeError('decision value is invalid');
    return 'domain';
  }
  if (name === 'ip' || name === '') {
    if (!isIpv4(value) && !isIpv6(value)) throw new TypeError('decision value is invalid');
    return 'ip';
  }
  throw new TypeError('decision scope is invalid');
}

/**
 * @param {unknown} raw
 */
function durationMs(raw) {
  if (typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= 366 * 86400) {
    return raw * 1000;
  }
  const match = typeof raw === 'string' ? /^(\d+)(s|m|h|d)$/.exec(raw) : null;
  if (!match) throw new TypeError('decision duration is invalid');
  const n = Number(match[1]);
  const unit =
    match[2] === 's' ? 1000 : match[2] === 'm' ? 60_000 : match[2] === 'h' ? 3_600_000 : DAY;
  if (n > 366 && match[2] === 'd') throw new TypeError('decision duration is invalid');
  return n * unit;
}

/**
 * @param {string} token
 */
function isIpv4(token) {
  const parts = token.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

/**
 * @param {string} token
 */
function isIpv6(token) {
  if (token.length > 45 || token.includes('.')) return false;
  if (!/^[0-9a-f:]+$/i.test(token)) return false;
  return token.split(':').length >= 3;
}

/**
 * @param {string} token
 */
function isCidr(token) {
  const cut = token.split('/');
  if (cut.length !== 2 || !isIpv4(cut[0]) || !/^\d{1,2}$/.test(cut[1])) return false;
  return Number(cut[1]) <= 32;
}

/**
 * @param {string} token
 */
function isDomain(token) {
  if (token.length > 253) return false;
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(
    token,
  );
}

module.exports = { parseDecisions, loadDecisionsFile };
