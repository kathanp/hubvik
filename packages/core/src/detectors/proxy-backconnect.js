'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'proxy-backconnect',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.4',
    fpRisk: '',
    attack: ['T1090'],
    stage: 'c2',
  },
  requires: ['T1'],
  category: 'proxy',
  defaults: { controlMs: 60000, burstMs: 5000, minBursts: 8, severity: 'critical' },

  createState() {
    return { controlTs: null, dsts: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out' || dev.fired) return;
    if ((ev.durationMs || 0) >= ctx.options.controlMs) {
      dev.controlTs = ev.ts;
      dev.dsts = new Set();
      return;
    }
    if (dev.controlTs == null || ev.ts - dev.controlTs > ctx.options.burstMs) return;
    if ((ev.durationMs || 0) > 2000) return;
    if (dev.dsts.size < 64) dev.dsts.add(ev.dstIp);
    if (dev.dsts.size < ctx.options.minBursts) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${dev.dsts.size} short flows after a long session`,
      expected: 'no burst of new flows tied to one control session',
      data: { destinations: dev.dsts.size },
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
    dev.controlTs = null;
    dev.dsts = new Set();
  },

  memoryEstimate() {
    return 32;
  },
};

module.exports = detector;
