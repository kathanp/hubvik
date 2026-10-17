'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'dhcp-starvation',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Low',
  },
  requires: ['T4'],
  category: 'link',
  defaults: { minMacs: 20, severity: 'high' },

  createState() {
    return {};
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dhcp' || ev.msg !== 'discover' || !ev.mac) return;
    const start = ctx.window && ctx.window.start;
    let bag = ctx.scratch.get('dhcp-starvation');
    if (!bag || bag.win !== start) {
      bag = { win: start, macs: new Set(), fired: false };
      ctx.scratch.set('dhcp-starvation', bag);
    }
    if (bag.macs.size < 5000) bag.macs.add(ev.mac);
    if (bag.fired || bag.macs.size <= ctx.options.minMacs) return;
    bag.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${bag.macs.size} DHCP discovers`,
      expected: `<= ${ctx.options.minMacs} new MACs per window`,
      data: { macs: bag.macs.size },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
  },

  memoryEstimate() {
    return 8;
  },
};

module.exports = detector;
