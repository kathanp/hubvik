'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'gratuitous-arp-flood',
  version: 1,
  meta: {
    consumes: ['arp'],
    rel: '0.3',
    fpRisk: 'Low',
  },
  requires: ['T4'],
  category: 'link',
  defaults: { minCount: 30, severity: 'high' },

  createState() {
    return { win: null, count: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'arp' || ev.op !== 'gratuitous') return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.count = 0;
      dev.fired = false;
    }
    dev.count += 1;
    if (dev.fired || dev.count <= ctx.options.minCount) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${dev.count} gratuitous ARP`,
      expected: `<= ${ctx.options.minCount} per window`,
      data: { count: dev.count },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.count = 0;
    dev.fired = false;
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
