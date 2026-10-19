'use strict';

const { explainMatch } = require('./lib');

const detector = {
  id: 'state-cap',
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
  defaults: { severity: 'medium' },

  createState() {
    return { fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!ctx.extra || ctx.extra.kind !== 'state-cap') return;
    if (dev.fired) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 1,
      ts: ev.ts,
      actual: 'state cap reached',
      expected: 'tracking within configured caps',
      data: { cap: ctx.extra && ctx.extra.cap ? ctx.extra.cap : 'devices' },
      explain: explainMatch({
        observed: 'state cap reached',
        matched: ctx.extra && ctx.extra.cap ? ctx.extra.cap : 'devices',
        source: 'cap',
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired === true };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    dev.fired = Boolean(state && state.fired);
  },

  memoryEstimate() {
    return 8;
  },
};

module.exports = detector;
