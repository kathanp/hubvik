'use strict';

const { isGroupDst } = require('../detectors/lib');
const { domainFamily, ipv4, inBlock } = require('./net');

const LAN_CAP = 32;
const WAN_CAP = 64;

/**
 * @param {any} engine
 * @returns {boolean}
 */
function graphOn(engine) {
  if (engine.opts.graph === false) return false;
  if (engine.opts.graph === true) return true;
  return ['graph-new-bridge', 'graph-role-change'].some((id) => {
    const status = engine.detectorStatus[id];
    return status && status.active;
  });
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @returns {void}
 */
function noteGraph(engine, device, event) {
  if (!engine._graphOn || !event || event.type !== 'flow') return;
  if (isGroupDst(event.dstIp) || isGroupDst(event.srcIp)) return;
  if (event.direction === 'lan') noteLan(engine, device, event);
  else if (event.direction === 'out') noteWan(device, event);
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 */
function noteLan(engine, device, event) {
  const dst = engine.resolve(event.dstIp);
  if (!dst || dst === device.id) return;
  const key = `${dst}\0${event.dstPort}\0${event.proto || ''}`;
  const row = touch(lanes(device), key, LAN_CAP);
  if (row.firstTs == null) {
    row.firstTs = event.ts;
    row.learned = device.mode === 'learning';
    row.flows = 0;
  }
  row.lastTs = event.ts;
  row.flows += 1;
  row.dst = dst;
  row.dstIp = event.dstIp;
  row.dstPort = event.dstPort;
  row.proto = event.proto || '';
  const peer = engine.devices.get(dst);
  if (!peer) return;
  if (!peer.lanPeers) peer.lanPeers = new Set();
  peer.lanPeers.add(device.id);
}

/**
 * @param {any} device
 * @param {any} event
 */
function noteWan(device, event) {
  const family = event.dstName ? domainFamily(event.dstName) : null;
  const key = family || slash24(event.dstIp);
  if (!key) return;
  const row = touch(wans(device), key, WAN_CAP);
  if (row.firstTs == null) {
    row.firstTs = event.ts;
    row.learned = device.mode === 'learning';
    row.bytesOut = 0;
  }
  row.lastTs = event.ts;
  row.bytesOut += event.bytesOut || 0;
}

/**
 * @param {Map<string, any>} map
 * @param {string} key
 * @param {number} cap
 */
function touch(map, key, cap) {
  const existing = map.get(key);
  if (existing) {
    map.delete(key);
    map.set(key, existing);
    return existing;
  }
  while (map.size >= cap) {
    const oldest = map.keys().next().value;
    if (oldest == null) break;
    map.delete(oldest);
  }
  const row = { firstTs: null, lastTs: null, learned: false };
  map.set(key, row);
  return row;
}

/**
 * @param {any} device
 */
function lanes(device) {
  if (!device.lanEdges) device.lanEdges = new Map();
  return device.lanEdges;
}

/**
 * @param {any} device
 */
function wans(device) {
  if (!device.wanEdges) device.wanEdges = new Map();
  return device.wanEdges;
}

/**
 * @param {string} ip
 * @returns {string | null}
 */
function slash24(ip) {
  const addr = ipv4(ip);
  if (addr == null) return null;
  return `${(addr >>> 24) & 255}.${(addr >>> 16) & 255}.${(addr >>> 8) & 255}.0/24`;
}

/**
 * @param {{ id: string, base: number, bits: number }[]} zones
 * @param {string} ip
 * @returns {string | null}
 */
function zoneOf(zones, ip) {
  const addr = typeof ip === 'string' ? ipv4(ip) : null;
  if (addr == null) return null;
  for (const zone of zones) {
    if (inBlock(addr, zone.base, zone.bits)) return zone.id;
  }
  return null;
}

/**
 * @param {any} engine
 * @param {{ device?: string, includeWan?: boolean }} [opts]
 */
function snapshot(engine, opts = {}) {
  /** @type {any[]} */
  const nodes = [];
  /** @type {any[]} */
  const lan = [];
  /** @type {any[]} */
  const wan = [];
  const ids = opts.device ? [opts.device] : [...engine.devices.keys()];
  for (const id of ids) {
    const device = engine.devices.get(id);
    if (!device) continue;
    nodes.push(id);
    if (device.lanEdges) {
      for (const row of device.lanEdges.values()) {
        lan.push({
          src: id,
          dst: row.dst,
          dstPort: row.dstPort,
          proto: row.proto,
          firstTs: row.firstTs,
          lastTs: row.lastTs,
          flows: row.flows,
          learned: row.learned,
        });
      }
    }
    if (opts.includeWan && device.wanEdges) {
      for (const [family, row] of device.wanEdges) {
        wan.push({
          src: id,
          family,
          firstTs: row.firstTs,
          lastTs: row.lastTs,
          bytesOut: row.bytesOut,
          learned: row.learned,
        });
      }
    }
  }
  return { nodes, lan, wan };
}

/**
 * @param {any} engine
 */
function exportGraph(engine) {
  const body = snapshot(engine, { includeWan: true });
  if (body.lan.length === 0 && body.wan.length === 0) return null;
  return body;
}

/**
 * @param {any} engine
 * @param {any} raw
 */
function importGraph(engine, raw) {
  if (raw == null) return;
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.lan) || !Array.isArray(raw.wan)) {
    throw new Error('checkpoint graph is invalid');
  }
  if (raw.lan.length > engine.opts.maxDevices * LAN_CAP) throw new Error('array graph exceeds cap');
  for (const edge of raw.lan) {
    if (!edge || typeof edge.src !== 'string' || typeof edge.dst !== 'string') {
      throw new Error('checkpoint graph is invalid');
    }
    const device = engine.devices.get(edge.src);
    if (!device) continue;
    const key = `${edge.dst}\0${edge.dstPort}\0${edge.proto || ''}`;
    lanes(device).set(key, {
      dst: edge.dst,
      dstPort: edge.dstPort,
      proto: edge.proto || '',
      firstTs: edge.firstTs,
      lastTs: edge.lastTs,
      flows: edge.flows || 0,
      learned: Boolean(edge.learned),
    });
  }
  for (const edge of raw.wan) {
    if (!edge || typeof edge.src !== 'string' || typeof edge.family !== 'string') {
      throw new Error('checkpoint graph is invalid');
    }
    const device = engine.devices.get(edge.src);
    if (!device) continue;
    wans(device).set(edge.family, {
      firstTs: edge.firstTs,
      lastTs: edge.lastTs,
      bytesOut: edge.bytesOut || 0,
      learned: Boolean(edge.learned),
    });
  }
}

module.exports = {
  LAN_CAP,
  WAN_CAP,
  graphOn,
  noteGraph,
  zoneOf,
  snapshot,
  exportGraph,
  importGraph,
};
