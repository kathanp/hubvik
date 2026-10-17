'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'lan-via-proxy',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'proxy',
  defaults: { followMs: 1000, severity: 'critical' },

  createState() {
    return { inboundTs: null, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || dev.fired) return;
    if (ev.direction === 'in' && (ev.bytesIn || 0) > 0) {
      dev.inboundTs = ev.ts;
      return;
    }
    if (ev.direction !== 'lan' || dev.inboundTs == null) return;
    if (ev.ts - dev.inboundTs > ctx.options.followMs) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `LAN flow to ${ev.dstIp} just after inbound bytes`,
      expected: 'LAN sessions that are not tied to a fresh WAN session',
      data: { dstIp: ev.dstIp, delayMs: ev.ts - dev.inboundTs },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = Boolean(state && state.fired);
    dev.inboundTs = null;
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
