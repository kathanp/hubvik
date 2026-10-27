'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'icmp-tunnel',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
    attack: ['T1572'],
  },
  requires: ['T1'],
  category: 'tunnel',
  defaults: { minBytesPerPacket: 200, severity: 'high' },

  createState() {
    return { fired: false };
  },

  /** @param {any} ev */
  prepare(ev) {
    return ev.type === 'flow' && ev.proto === 'icmp' && ev.icmpType !== 5;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || ev.type !== 'flow' || ev.proto !== 'icmp' || ev.icmpType === 5) return;
    const pkts = (ev.pktsOut || 0) + (ev.pktsIn || 0);
    const bytes = (ev.bytesOut || 0) + (ev.bytesIn || 0);
    if (pkts <= 0 || bytes / pkts < ctx.options.minBytesPerPacket) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${Math.round(bytes / pkts)} bytes/packet`,
      expected: `< ${ctx.options.minBytesPerPacket} bytes per ICMP packet`,
      data: { bytes, pkts },
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
  },

  memoryEstimate() {
    return 8;
  },
};

module.exports = detector;
