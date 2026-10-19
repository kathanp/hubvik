'use strict';

const { ipv4 } = require('./net');

const DAY = 24 * 3600e3;
const MAX_ROWS = 50_000;
const MAX_PER_MAC = 16;

/**
 * @param {string} mac
 * @returns {boolean}
 */
function isMac(mac) {
  return typeof mac === 'string' && /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(mac);
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isIpv6(ip) {
  return typeof ip === 'string' && ip.includes(':') && ip.length <= 45 && /^[0-9a-f:]+$/i.test(ip);
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function looksLikeIp(value) {
  return ipv4(value) != null || isIpv6(value);
}

/**
 * @param {Map<string, { mac: string, source: string, lastTs: number }>} map
 * @param {number} ts
 */
function dropStale(map, ts) {
  for (const [ip, row] of map) {
    if (isIpv6(ip) && ts - row.lastTs > DAY) map.delete(ip);
  }
}

/**
 * @param {Map<string, { mac: string, source: string, lastTs: number }>} map
 * @param {string} ip
 * @param {string} mac
 * @param {'dhcp' | 'arp' | 'nd'} source
 * @param {number} ts
 */
function remember(map, ip, mac, source, ts) {
  if (!ip || !isMac(mac)) return;
  if (source === 'nd' && !isIpv6(ip)) return;
  if (source !== 'nd' && ipv4(ip) == null && !isIpv6(ip)) return;
  dropStale(map, ts);
  const existing = map.get(ip);
  if (existing) {
    existing.mac = mac;
    existing.source = source;
    existing.lastTs = ts;
    return;
  }
  /** @type {[string, number][]} */
  const owned = [];
  for (const [key, row] of map) {
    if (row.mac === mac) owned.push([key, row.lastTs]);
  }
  if (owned.length >= MAX_PER_MAC) {
    owned.sort((a, b) => a[1] - b[1]);
    map.delete(owned[0][0]);
  }
  if (map.size >= MAX_ROWS) {
    let oldest = null;
    let oldestTs = Infinity;
    for (const [key, row] of map) {
      if (row.lastTs < oldestTs) {
        oldestTs = row.lastTs;
        oldest = key;
      }
    }
    if (oldest != null) map.delete(oldest);
  }
  map.set(ip, { mac, source, lastTs: ts });
}

/**
 * @param {any} engine
 * @returns {Map<string, { mac: string, source: string, lastTs: number }>}
 */
function tableOf(engine) {
  let map = engine.scratch.get('identity');
  if (!(map instanceof Map)) {
    map = new Map();
    engine.scratch.set('identity', map);
  }
  return map;
}

/**
 * Record a DHCP, ARP, or neighbor-discovery binding.
 * @param {any} engine
 * @param {any} event
 */
function noteIdentity(engine, event) {
  const map = tableOf(engine);
  if (
    event.type === 'dhcp' &&
    (event.msg === 'ack' || event.msg === 'offer') &&
    event.requestedIp &&
    event.mac
  ) {
    remember(map, event.requestedIp, event.mac, 'dhcp', event.ts);
  } else if (
    event.type === 'arp' &&
    event.ip &&
    event.mac &&
    (event.op === 'reply' || event.op === 'gratuitous')
  ) {
    remember(map, event.ip, event.mac, 'arp', event.ts);
  } else if (event.type === 'nd' && event.ip && event.mac) {
    remember(map, event.ip, event.mac, 'nd', event.ts);
  }
}

/**
 * When identity is auto, an IP used as a device id follows its MAC.
 * @param {any} engine
 * @param {any} event
 */
function rekeyIdentity(engine, event) {
  if (engine.opts.identity !== 'auto') return;
  if (!looksLikeIp(event.device)) return;
  const map = tableOf(engine);
  dropStale(map, event.ts);
  const row = map.get(event.device);
  if (!row) {
    engine._unresolved = (engine._unresolved || 0) + 1;
    return;
  }
  if (row.mac === event.device) return;
  event.observedAs = event.device;
  event.device = row.mac;
  row.lastTs = event.ts;
  engine._rekeyed = (engine._rekeyed || 0) + 1;
}

/**
 * @param {any} engine
 * @param {string} ip
 * @returns {string | null}
 */
function resolveIp(engine, ip) {
  if (typeof ip !== 'string') return null;
  const map = engine.scratch.get('identity');
  if (!(map instanceof Map)) return null;
  const row = map.get(ip);
  if (!row || typeof row.mac !== 'string') return null;
  if (isIpv6(ip) && typeof engine.watermark === 'number' && engine.watermark - row.lastTs > DAY) {
    return null;
  }
  return row.mac;
}

module.exports = {
  MAX_ROWS,
  isMac,
  isIpv6,
  noteIdentity,
  rekeyIdentity,
  resolveIp,
};
