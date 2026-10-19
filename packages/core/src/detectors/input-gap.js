'use strict';

const { explainThreshold } = require('./lib');

const detector = {
  id: 'input-gap',
  version: 1,
  meta: {
    consumes: [],
    rel: '0.2',
    fpRisk: '',
    explains: true,
  },
  requires: ['T0'],
  category: 'integrity',
  hardRule: true,
  defaults: { severity: 'high' },

  createState() {
    return {};
  },

  /**
   * Called by the engine from flush, not from ordinary device traffic.
   * @param {any} _dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(_dev, ev, ctx) {
    if (!ctx.extra || ctx.extra.kind !== 'input-gap') return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `no events for ${Math.round(ev.gapMs / 3600e3)}h`,
      expected: 'a live event stream',
      data: { gapMs: ev.gapMs },
      explain: explainThreshold({
        test: 'gte',
        observed: ev.gapMs,
        threshold: 24 * 3600e3,
        formula: 'gapMs>=24h',
      }),
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
