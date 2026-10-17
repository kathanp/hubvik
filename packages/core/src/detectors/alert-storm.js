'use strict';

const detector = {
  id: 'alert-storm',
  version: 1,
  meta: {
    consumes: [],
    rel: '0.2',
    fpRisk: '',
  },
  requires: ['T0'],
  category: 'integrity',
  hardRule: true,
  defaults: { maxPerMinute: 1000, severity: 'medium' },

  createState() {
    return {};
  },

  /** @param {any} _dev @param {any} ev @param {any} ctx */
  check(_dev, ev, ctx) {
    if (!ctx.extra || ctx.extra.kind !== 'alert-storm') return;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.count} anomalies in one minute`,
      expected: `<= ${ctx.options.maxPerMinute} anomalies/minute`,
      data: { count: ev.count },
    };
  },

  exportState() {
    return {};
  },

  importState() {},

  memoryEstimate() {
    return 8;
  },
};

module.exports = detector;
