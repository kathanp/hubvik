'use strict';

const { HubvikError } = require('../errors');

const { ipv4, inBlock, isPublic } = require('../engine/net');
const { scratchBag } = require('./lib');
const { assertState } = require('./state');

const CAP = 64;

/**
 * @param {string} cidr
 * @returns {number}
 */
function prefixBits(cidr) {
  const bits = Number(cidr.slice(cidr.lastIndexOf('/') + 1));
  return Number.isInteger(bits) ? bits : 99;
}

/**
 * @param {string} cidr
 * @param {string} ip
 * @returns {boolean}
 */
function covers(cidr, ip) {
  const slash = cidr.lastIndexOf('/');
  const base = ipv4(cidr.slice(0, slash));
  const addr = ipv4(ip);
  const bits = prefixBits(cidr);
  if (base == null || addr == null || bits > 32) return false;
  return inBlock(addr, base, bits);
}

/**
 * @param {any} ctx
 * @param {any} ev
 * @param {boolean} record
 * @returns {Set<number>}
 */
function noteServer(ctx, ev, record) {
  const bag = scratchBag(ctx, 'dhcp-route-injection', () => ({ servers: new Map() }));
  let set = bag.servers.get(ev.serverIp);
  if (!set) {
    if (bag.servers.size >= CAP) {
      const oldest = bag.servers.keys().next().value;
      if (oldest !== undefined) bag.servers.delete(oldest);
    }
    set = new Set();
    bag.servers.set(ev.serverIp, set);
  }
  if (record && Array.isArray(ev.options)) {
    for (const code of ev.options) set.add(code);
  }
  return set;
}

const detector = {
  id: 'dhcp-route-injection',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low. Enterprise networks that push 121 legitimately are absorbed by the learned set',
    consumes: ['dhcp', 'flow'],
    attack: ['T1557'],
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { ips: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    if (ev.type === 'flow' && isPublic(ev.dstIp) && dev.ips.size < CAP) dev.ips.add(ev.dstIp);
    if (ev.type === 'dhcp' && ev.serverIp && (ev.msg === 'offer' || ev.msg === 'ack')) {
      noteServer(ctx, ev, true);
    }
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type === 'flow' && isPublic(ev.dstIp) && dev.ips.size < CAP) dev.ips.add(ev.dstIp);
    if (ev.type !== 'dhcp' || !ev.serverIp || (ev.msg !== 'offer' && ev.msg !== 'ack')) return;
    const known = noteServer(ctx, ev, false);
    const options = Array.isArray(ev.options) ? ev.options : [];
    const routes = Array.isArray(ev.routes) ? ev.routes : [];
    const injected = options.some((/** @type {number} */ code) => {
      return (code === 121 || code === 249) && !known.has(code);
    });
    const wide = routes.some((/** @type {string} */ route) => {
      const bits = prefixBits(route);
      return bits === 0 || bits === 1;
    });
    let covered = false;
    for (const route of routes) {
      for (const ip of dev.ips) {
        if (covers(route, ip)) covered = true;
      }
    }
    if (!injected && !wide && !covered) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.serverIp} routes ${routes.join(',')}`,
      expected: 'DHCP routes this server already sent',
      data: { serverIp: ev.serverIp, routes },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { ips: [...dev.ips] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.ips = new Set();
    if (!state || !Array.isArray(state.ips)) return;
    if (state.ips.length > CAP) throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array ips exceeds cap');
    for (const ip of state.ips) dev.ips.add(String(ip));
  },

  memoryEstimate() {
    return 128;
  },
};

module.exports = detector;
