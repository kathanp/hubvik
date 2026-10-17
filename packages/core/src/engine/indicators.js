'use strict';

const { ipv4, inBlock } = require('./net');

/**
 * @param {any[]} list
 */
function buildIndex(list) {
  /** @type {Map<string, any>} */
  const exact = new Map();
  /** @type {Map<number, Map<number, any>>} */
  const v4 = new Map();
  for (const item of list) {
    if (item.type === 'cidr') {
      const slash = item.value.lastIndexOf('/');
      const base = ipv4(item.value.slice(0, slash));
      const bits = Number(item.value.slice(slash + 1));
      if (base == null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      const network = (base & mask) >>> 0;
      let bucket = v4.get(bits);
      if (!bucket) {
        bucket = new Map();
        v4.set(bits, bucket);
      }
      bucket.set(network, item);
    } else {
      exact.set(`${item.type}|${String(item.value).toLowerCase()}`, item);
    }
  }
  return { exact, v4 };
}

/**
 * @param {any} item
 * @param {number} ts
 * @returns {boolean}
 */
function live(item, ts) {
  return item.expiresTs == null || ts < item.expiresTs;
}

/**
 * @param {{ exact: Map<string, any>, v4: Map<number, Map<number, any>> }} index
 * @param {string} type
 * @param {string} value
 * @param {number} ts
 * @returns {any | null}
 */
function exactHit(index, type, value, ts) {
  const item = index.exact.get(`${type}|${value.toLowerCase()}`);
  if (item && live(item, ts)) return item;
  return null;
}

/**
 * Walk parent labels so `a.evil.example` matches an indicator for `evil.example`.
 * @param {{ exact: Map<string, any>, v4: Map<number, Map<number, any>> }} index
 * @param {string} name
 * @param {number} ts
 * @returns {any | null}
 */
function domainHit(index, name, ts) {
  const labels = name.toLowerCase().split('.').filter(Boolean);
  for (let i = 0; i < labels.length - 1; i++) {
    const hit = exactHit(index, 'domain', labels.slice(i).join('.'), ts);
    if (hit) return hit;
  }
  return null;
}

/**
 * @param {{ exact: Map<string, any>, v4: Map<number, Map<number, any>> }} index
 * @param {string} ip
 * @param {number} ts
 * @returns {any | null}
 */
function cidrHit(index, ip, ts) {
  const value = ipv4(ip);
  if (value == null) return null;
  for (const [bits, bucket] of index.v4) {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const network = (value & mask) >>> 0;
    const item = bucket.get(network);
    if (item && live(item, ts) && inBlock(value, network, bits)) return item;
  }
  return null;
}

/**
 * @param {{ exact: Map<string, any>, v4: Map<number, Map<number, any>> } | null} index
 * @param {any} event
 * @returns {any | null}
 */
function matchEvent(index, event) {
  if (!index) return null;
  const ts = event.ts || 0;
  const names = [event.dst, event.dstName, event.qname, event.sni, event.host].filter(
    (value) => typeof value === 'string' && value.length > 0,
  );
  const ips = [event.dstIp, event.dst].filter((value) => typeof value === 'string');
  for (const ip of ips) {
    const hit = exactHit(index, 'ip', ip, ts) || cidrHit(index, ip, ts);
    if (hit) return hit;
  }
  for (const name of names) {
    const hit = domainHit(index, name, ts);
    if (hit) return hit;
  }
  if (typeof event.ja4 === 'string') {
    const hit = exactHit(index, 'ja4', event.ja4, ts);
    if (hit) return hit;
  }
  return null;
}

module.exports = { buildIndex, matchEvent, exactHit };
