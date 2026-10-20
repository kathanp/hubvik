'use strict';

const { domainToASCII } = require('node:url');
const { TIER_SET, FORBIDDEN_KEYS, SEVERITY_NAMES } = require('../constants');
const { ipv4 } = require('../net');

/**
 * @param {string} key
 * @returns {void}
 */
function assertSafeKey(key) {
  if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden key ${key}`);
}

/**
 * @param {object} value
 * @param {string} path
 * @returns {void}
 */
function assertSafeKeys(value, path) {
  if (!value || typeof value !== 'object') return;
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden key ${key} at ${path}`);
  }
  for (const key of FORBIDDEN_KEYS) {
    if (Object.hasOwn(value, key)) throw new Error(`forbidden key ${key} at ${path}`);
  }
}

/**
 * @param {unknown} value
 * @param {string} name
 * @returns {boolean}
 */
function bool(value, name) {
  if (typeof value !== 'boolean') throw new TypeError(`${name} must be a boolean`);
  return value;
}

/**
 * @param {unknown} value
 * @returns {'off' | 'auto'}
 */
function identityMode(value) {
  if (value === 'off' || value === 'auto') return value;
  throw new TypeError('identity must be off or auto');
}

/**
 * Shadow detectors stay off unless the host opts in.
 * @param {unknown} value
 * @returns {boolean | string[]}
 */
function parseShadow(value) {
  if (value == null || value === false) return false;
  if (value === true) return true;
  if (!Array.isArray(value)) throw new TypeError('shadow must be false, true, or an array of ids');
  /** @type {string[]} */
  const ids = [];
  for (const id of value) {
    if (typeof id !== 'string' || !/^(?:rule:)?[a-z0-9-]+$/.test(id)) {
      throw new TypeError('shadow id is invalid');
    }
    ids.push(id);
  }
  return ids;
}

/**
 * Default is off. An object uses 3 days and 10 hits unless the host sets them.
 * @param {any} input
 * @returns {false | { afterDays: number, minHits: number }}
 */
function parsePromote(input) {
  if (input.promote == null || input.promote === false) return false;
  const raw = input.promote;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('promote must be false or an object');
  }
  assertSafeKeys(raw, 'promote');
  return {
    afterDays:
      raw.afterDays == null
        ? 3
        : num(raw.afterDays, 'promote.afterDays', { min: 1, integer: true }),
    minHits:
      raw.minHits == null ? 10 : num(raw.minHits, 'promote.minHits', { min: 1, integer: true }),
  };
}

/**
 * @param {number} value
 * @param {string} name
 * @param {{ min?: number, max?: number, integer?: boolean }} [rule]
 * @returns {number}
 */
function num(value, name, rule = {}) {
  const min = rule.min ?? 0;
  const max = rule.max ?? Number.POSITIVE_INFINITY;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    throw new TypeError(`${name} must be a finite number >= ${min}`);
  }
  if (rule.integer && !Number.isInteger(value)) throw new TypeError(`${name} must be an integer`);
  return value;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isV4(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    if (n > 255) return false;
  }
  return true;
}

/**
 * @param {string} ip
 * @returns {string | null}
 */
function normalizeIp(ip) {
  let s = ip.toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped && isV4(mapped[1])) return mapped[1];
  if (s.includes(':') || isV4(s)) return s;
  return null;
}

/**
 * Lowercase, strip a trailing dot, punycode a hostname, unwrap IPv4-mapped IPv6.
 * @param {unknown} value
 * @param {number} maxString
 * @returns {string | null}
 */
function normalizeName(value, maxString) {
  if (typeof value !== 'string') return null;
  let s = value.trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (!s || s.length > maxString) return null;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.includes(':') || isV4(s)) return normalizeIp(s);
  let ascii;
  try {
    ascii = domainToASCII(s);
  } catch {
    return null;
  }
  if (!ascii || ascii.length > maxString) return null;
  return ascii;
}

/**
 * @param {any} raw
 * @param {string[]} fields
 * @param {string} type
 */
function requireFields(raw, fields, type) {
  for (const field of fields) {
    if (raw[field] == null) throw new TypeError(`${type} event requires ${field}`);
  }
}

/** @param {number} ts */
function defaultHour(ts) {
  return new Date(ts).getUTCHours();
}

/** @param {number} ts */
function defaultDay(ts) {
  return Math.floor(ts / 86400000);
}

/**
 * @param {any} input
 * @returns {any[]}
 */
/**
 * @param {any} input
 */
function parseLookup(input) {
  if (input.lookup == null) return null;
  if (typeof input.lookup !== 'function') throw new TypeError('lookup must be a function');
  return input.lookup;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string | null}
 */
function parseOptionalString(value, label) {
  if (value == null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string[]}
 */
function parseStringList(value, label) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > 32) throw new TypeError(`${label} is invalid`);
  return value.map((item) => {
    if (typeof item !== 'string' || item.length === 0 || item.length > 255) {
      throw new TypeError(`${label} is invalid`);
    }
    return item;
  });
}

/**
 * @param {any} input
 * @returns {{ id: string, base: number, bits: number }[]}
 */
function parseZones(input) {
  if (input.zones == null) return [];
  if (!Array.isArray(input.zones) || input.zones.length > 64) {
    throw new TypeError('zones are invalid');
  }
  return input.zones.map((/** @type {any} */ zone, /** @type {number} */ index) => {
    if (!zone || typeof zone !== 'object' || Array.isArray(zone)) {
      throw new TypeError('zone is invalid');
    }
    assertSafeKeys(zone, `zones[${index}]`);
    if (typeof zone.id !== 'string' || !/^[a-z0-9-]+$/.test(zone.id)) {
      throw new TypeError('zone id is invalid');
    }
    const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(zone.cidr || ''));
    const base = match ? ipv4(match[1]) : null;
    const bits = match ? Number(match[2]) : -1;
    if (base == null || bits < 0 || bits > 32) throw new TypeError('zone cidr is invalid');
    return { id: zone.id, base, bits };
  });
}

/**
 * @param {any} input
 * @returns {any[]}
 */
function parsePolicy(input) {
  if (input.policy == null) return [];
  if (!Array.isArray(input.policy)) throw new TypeError('policy must be an array');
  if (input.policy.length > 256) throw new TypeError('policy exceeds cap');
  return input.policy.map((/** @type {any} */ rule, /** @type {number} */ index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new TypeError('policy rule is invalid');
    }
    assertSafeKeys(rule, `policy[${index}]`);
    if (typeof rule.id !== 'string' || !/^[a-z0-9-]+$/.test(rule.id)) {
      throw new TypeError('policy id is invalid');
    }
    if (!rule.match || typeof rule.match !== 'object' || Array.isArray(rule.match)) {
      throw new TypeError('policy match is invalid');
    }
    assertSafeKeys(rule.match, `policy[${index}].match`);
    if (rule.severity != null && !SEVERITY_NAMES.has(rule.severity)) {
      throw new TypeError('policy severity is invalid');
    }
    return { id: rule.id, severity: rule.severity, match: rule.match };
  });
}

/**
 * Per-tier silence limits. T4 defaults to 26 h because DHCP and ARP are often daily.
 * @param {unknown} input
 * @returns {Record<string, number>}
 */
function tierLimits(input) {
  /** @type {Record<string, number>} */
  const out = { T4: 26 * 3600e3 };
  if (input == null) return out;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('tierSilentByTier must be an object');
  }
  assertSafeKeys(input, 'tierSilentByTier');
  for (const [tier, value] of Object.entries(input)) {
    if (!TIER_SET.has(tier)) throw new TypeError(`tierSilentByTier.${tier} is invalid`);
    out[tier] = num(value, `tierSilentByTier.${tier}`, { min: 1, integer: true });
  }
  return out;
}

module.exports = {
  assertSafeKey,
  assertSafeKeys,
  bool,
  identityMode,
  parseShadow,
  parsePromote,
  num,
  isV4,
  normalizeIp,
  normalizeName,
  requireFields,
  defaultHour,
  defaultDay,
  parseLookup,
  parseOptionalString,
  parseStringList,
  parseZones,
  parsePolicy,
  tierLimits,
};
