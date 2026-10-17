'use strict';

const detector = {
  id: 'new-device',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low',
  },
  requires: ['T0'],
  category: 'link',
  hardRule: true,
  defaults: { severity: 'medium' },

  createState() {
    return { seen: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.seen) return;
    dev.seen = true;
    if (ctx.engineStarted == null || ev.ts - ctx.engineStarted <= ctx.learnMs) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: ev.device || ctx.deviceId,
      expected: 'devices seen before learning finished',
      data: { firstTs: ev.ts },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { seen: dev.seen };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    dev.seen = Boolean(state && state.seen);
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
