'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'supply-chain-suspect',
  version: 1,
  meta: {
    consumes: [],
    rel: '0.3',
    fpRisk: '',
    attack: ['T1195'],
  },
  requires: ['T0'],
  category: 'proxy',
  hardRule: true,
  defaults: { severity: 'critical' },

  createState() {
    return { fired: false, because: null };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!ctx.extra || ctx.extra.kind !== 'supply' || dev.fired) return;
    dev.fired = true;
    dev.because = ctx.extra.because || 'unknown';
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: dev.because,
      expected: 'no proxy, chain, or class violation while the device is still learning',
      data: { because: dev.because },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired, because: dev.because };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = Boolean(state && state.fired);
    dev.because = state && typeof state.because === 'string' ? state.because : null;
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
