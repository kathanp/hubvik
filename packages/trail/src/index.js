'use strict';

const { readFileSync } = require('node:fs');

const DEFAULT_MAX = 100_000;

/**
 * Turn a trail file the host already downloaded into indicator rows.
 * One host per line. Comments start with `#`. This function does not fetch.
 * @param {string} text
 * @param {{ source?: string, max?: number }} [opts]
 * @returns {{ value: string, type: string, source: string, confidence: number, expiresTs: null }[]}
 */
function parseTrail(text, opts = {}) {
  if (typeof text !== 'string') throw new TypeError('trail file is invalid');
  const max = opts.max == null ? DEFAULT_MAX : opts.max;
  if (!Number.isInteger(max) || max < 1) throw new TypeError('trail cap is invalid');
  const source = opts.source == null ? 'trail' : opts.source;
  if (typeof source !== 'string' || source.length === 0 || source.length > 255) {
    throw new TypeError('trail source is invalid');
  }
  /** @type {{ value: string, type: string, source: string, confidence: number, expiresTs: null }[]} */
  const rows = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const token = stripPort(trimmed);
    const type = kindOf(token);
    if (!type) throw new TypeError('trail line is invalid');
    rows.push({
      value: type === 'domain' ? token.toLowerCase() : token.toLowerCase(),
      type,
      source,
      confidence: 1,
      expiresTs: null,
    });
    if (rows.length > max) throw new TypeError('trail file exceeds cap');
  }
  return rows;
}

/**
 * Read a trail file the host downloaded. No network call.
 * @param {string} file
 * @param {{ source?: string, max?: number }} [opts]
 */
function loadTrailFile(file, opts) {
  if (typeof file !== 'string' || file.length === 0) throw new TypeError('trail file is invalid');
  return parseTrail(readFileSync(file, 'utf8'), opts);
}

/**
 * Drop a trailing :port from an IPv4 or a domain. Leave IPv6 alone.
 * @param {string} token
 */
function stripPort(token) {
  const cut = token.lastIndexOf(':');
  if (cut <= 0) return token;
  const port = token.slice(cut + 1);
  const left = token.slice(0, cut);
  if (!/^\d{1,5}$/.test(port) || Number(port) > 65535) return token;
  if (isIpv4(left) || left.includes('.')) return left;
  return token;
}

/**
 * @param {string} token
 * @returns {'ip' | 'cidr' | 'domain' | null}
 */
function kindOf(token) {
  if (token.includes('/')) return isCidr(token) ? 'cidr' : null;
  if (isIpv4(token) || isIpv6(token)) return 'ip';
  if (isDomain(token)) return 'domain';
  return null;
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

module.exports = { parseTrail, loadTrailFile };
