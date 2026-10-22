'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { scratchBag } = require('./lib');
const { assertState } = require('./state');

const DAY = 24 * 60 * 60 * 1000;

/**
 * @param {string | undefined} name
 * @returns {boolean}
 */
function wpadName(name) {
  if (!name) return false;
  const label = name.split('.')[0];
  return label === 'wpad';
}

/**
 * @param {any} ctx
 * @returns {{ servers: Set<string>, nx: Set<string> }}
 */
function bagOf(ctx) {
  return scratchBag(ctx, 'wpad-hijack', () => ({ servers: new Set(), nx: new Set() }));
}

const detector = {
  id: 'wpad-hijack',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low. Most home and building networks never answer WPAD',
    consumes: ['dhcp', 'dns'],
    attack: ['T1557'],
  },
  requires: ['T2'],
  category: 'link',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { fired: new Map() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    const bag = bagOf(ctx);
    if (ev.type === 'dhcp' && ev.serverIp && (ev.msg === 'offer' || ev.msg === 'ack')) {
      const options = Array.isArray(ev.options) ? ev.options : [];
      if (options.includes(252) || ev.wpadUrl) bag.servers.add(ev.serverIp);
    }
    if (ev.type === 'dns' && wpadName(ev.qname) && ev.rcode === 'NXDOMAIN') {
      const family = domainFamily(ev.qname) || ev.qname;
      if (bag.nx.size < 256) bag.nx.add(family);
    }
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const bag = bagOf(ctx);
    if (ev.type === 'dhcp' && ev.serverIp && (ev.msg === 'offer' || ev.msg === 'ack')) {
      const options = Array.isArray(ev.options) ? ev.options : [];
      if ((options.includes(252) || ev.wpadUrl) && !bag.servers.has(ev.serverIp)) {
        if (recent(dev, ev.serverIp, ev.ts)) return;
        dev.fired.set(ev.serverIp, ev.ts);
        return hit(ctx, ev, ev.serverIp, ev.wpadUrl || 'option 252');
      }
    }
    if (ev.type === 'dns' && wpadName(ev.qname) && ev.rcode === 'NOERROR') {
      const family = domainFamily(ev.qname) || ev.qname;
      if (!bag.nx.has(family)) return;
      const answer = ev.answers && ev.answers[0] ? String(ev.answers[0].value) : ev.resolver;
      if (recent(dev, answer, ev.ts)) return;
      dev.fired.set(answer, ev.ts);
      return hit(ctx, ev, answer, ev.qname);
    }
    return undefined;
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: [...dev.fired.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = new Map();
    if (!state || !Array.isArray(state.fired)) return;
    if (state.fired.length > 256)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array fired exceeds cap');
    for (const pair of state.fired) {
      if (Array.isArray(pair)) dev.fired.set(String(pair[0]), Number(pair[1]) || 0);
    }
  },

  memoryEstimate() {
    return 64;
  },
};

/**
 * @param {any} dev
 * @param {string} key
 * @param {number} ts
 * @returns {boolean}
 */
function recent(dev, key, ts) {
  const at = dev.fired.get(key);
  return typeof at === 'number' && ts - at < DAY;
}

/**
 * @param {any} ctx
 * @param {any} ev
 * @param {string} key
 * @param {string} detail
 */
function hit(ctx, ev, key, detail) {
  return {
    severity: ctx.options.severity,
    confidence: 0.85,
    ts: ev.ts,
    actual: `${key} ${detail}`,
    expected: 'no new WPAD offer or answer',
    data: { key, detail },
  };
}

module.exports = detector;
