'use strict';

const { createHmac } = require('node:crypto');
const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const detector = {
  id: 'peer-divergence-federated',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Medium', consumes: ['flow', 'dns', 'summary'] },
  requires: ['T0'],
  category: 'fleet',
  defaults: { enabled: true, severity: 'high' },

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
    if (!family || dev.fired.has(family)) return;
    if (dev.families.size < 64) dev.families.add(family);
    const summaries = typeof ctx.peerSummaries === 'function' ? ctx.peerSummaries() : [];
    const gateways = new Set();
    for (const row of summaries) {
      if (typeof row.gatewayId === 'string' && row.gatewayId.length > 0)
        gateways.add(row.gatewayId);
    }
    if (gateways.size < 3) return;
    const local = typeof ctx.peers === 'function' ? ctx.peers() : [];
    const peers = local.length + summaries.length;
    if (peers < 3) return;
    const key = typeof ctx.summaryKey === 'function' ? ctx.summaryKey() : null;
    const needle = key
      ? createHmac('sha256', key).update(family).digest('hex').slice(0, 16)
      : family;
    let have = 0;
    for (const peer of local) {
      const state = typeof ctx.peerState === 'function' ? ctx.peerState(peer, detector.id) : null;
      if (state && state.families && state.families.has(family)) have += 1;
    }
    for (const summary of summaries) {
      const hit = (summary.groups || []).some((/** @type {any} */ group) =>
        (group.families || []).includes(needle),
      );
      if (hit) have += 1;
    }
    if (have * 2 >= peers) return;
    dev.fired.add(family);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: family,
      expected: `a family shared by federated peers across ${gateways.size} gateways`,
      data: { family, gateways: gateways.size, have },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { families: [...dev.families], fired: [...dev.fired].slice(0, 64) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.families = new Set(
      Array.isArray(state.families) ? state.families.slice(0, 64).map(String) : [],
    );
    dev.fired = new Set(Array.isArray(state.fired) ? state.fired.slice(0, 64).map(String) : []);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.families.size * 24 + Math.min(dev.fired.size, 64) * 16 + 16;
  },
};

module.exports = detector;
