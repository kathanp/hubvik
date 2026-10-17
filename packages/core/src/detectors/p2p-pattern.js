'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'p2p-pattern',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.4',
    fpRisk: 'Medium (some cameras use P2P relay legitimately; baseline catches that)',
  },
  requires: ['T1'],
  category: 'proxy',
  defaults: { minPeers: 30, minInboundShare: 0.3, severity: 'high' },

  createState() {
    return { win: null, peers: new Set(), inbound: 0, total: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.dstPort <= 1024) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.peers = new Set();
      dev.inbound = 0;
      dev.total = 0;
      dev.fired = false;
    }
    dev.total += 1;
    if (ev.direction === 'in') dev.inbound += 1;
    if (dev.peers.size < 5000) dev.peers.add(ev.direction === 'in' ? ev.srcIp : ev.dstIp);
    if (dev.fired || dev.peers.size < ctx.options.minPeers) return;
    if (dev.inbound / dev.total < ctx.options.minInboundShare) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: `${dev.peers.size} high-port peers, both directions`,
      expected: `< ${ctx.options.minPeers} residential peers`,
      data: { peers: dev.peers.size, inboundShare: dev.inbound / dev.total },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.peers = new Set();
    dev.inbound = 0;
    dev.total = 0;
    dev.fired = false;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.peers.size * 16 + 16;
  },
};

module.exports = detector;
