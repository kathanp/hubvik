'use strict';

const { assertState } = require('./state');
const { explainThreshold } = require('./lib');

const detector = {
  id: 'post-update-drift',
  version: 1,
  meta: {
    consumes: [],
    rel: '0.3',
    fpRisk: '',
    explains: true,
  },
  requires: ['T0'],
  category: 'supply',
  hardRule: true,
  defaults: { severity: 'high' },

  createState() {
    return { fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!ctx.extra || ctx.extra.kind !== 'post-update-drift' || dev.fired) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `${ctx.extra.others} new behaviors after a download`,
      expected: 'a firmware update, or a compromise that arrived with one',
      data: { others: ctx.extra.others, updateId: ctx.extra.updateId },
      explain: explainThreshold({
        test: 'gte',
        observed: ctx.extra.others,
        threshold: 3,
        formula: 'others>=3',
      }),
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
