'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'ot-error-burst',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { minErrors: 10, severity: 'medium' },

  createState() {
    return { win: null, count: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || (ev.result !== 'error' && ev.result !== 'reject')) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.count = 0;
      dev.fired = false;
    }
    dev.count += 1;
    if (dev.fired || dev.count <= ctx.options.minErrors) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: `${dev.count} protocol errors`,
      expected: `<= ${ctx.options.minErrors} per window`,
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
