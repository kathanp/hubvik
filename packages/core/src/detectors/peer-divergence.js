'use strict';

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const detector = {
  id: 'peer-divergence',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T0'],
  category: 'fleet',
  defaults: { minPeers: 5, severity: 'high' },

  createState() {
    return { families: new Set(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const family = domainFamily(ev.dst || ev.dstName || ev.qname);
    if (family && dev.families.size < 64) dev.families.add(family);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const family = domainFamily(ev.dst || ev.dstName || ev.qname);
    if (!family) return;
    if (dev.families.size < 64) dev.families.add(family);
    if (dev.fired.has(family)) return;
    const peers = typeof ctx.peers === 'function' ? ctx.peers() : [];
    if (peers.length < ctx.options.minPeers) return;
    let have = 0;
    for (const peer of peers) {
      const state = ctx.peerState(peer, detector.id);
      if (state && state.families && state.families.has(family)) have += 1;
    }
    if (have * 2 >= peers.length) return;
    dev.fired.add(family);
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: family,
      expected: `a family shared by at least half of ${peers.length} peers`,
      data: { family, peers: peers.length, have },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { families: [...dev.families] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.families = new Set(Array.isArray(state.families) ? state.families.slice(0, 64) : []);
    dev.fired = new Set();
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.families.size * 24 + 16;
  },
};

module.exports = detector;
