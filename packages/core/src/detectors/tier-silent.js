'use strict';

const detector = {
  id: 'tier-silent',
  version: 1,
  meta: {
    rel: '0.5',
    fpRisk: '',
  },
  requires: ['T0'],
  category: 'integrity',
  hardRule: true,
  defaults: { tierSilentMs: 6 * 3600e3, severity: 'high' },

  createState() {
    return {};
  },

  /**
   * Called from tick when one enabled tier has gone quiet.
   * @param {any} _dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(_dev, ev, ctx) {
    if (!ctx.extra || ctx.extra.kind !== 'tier-silent') return;
    const names = Array.isArray(ctx.extra.detectors) ? ctx.extra.detectors : [];
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${ctx.extra.tier} silent: ${names.join(', ')}`,
      expected: 'events for every enabled tier',
      data: { tier: ctx.extra.tier, detectors: names },
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
