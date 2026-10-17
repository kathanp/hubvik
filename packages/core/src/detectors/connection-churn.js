'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'connection-churn',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Low',
  },
  requires: ['T1'],
  category: 'volume',
  defaults: { minCount: 50, factor: 3, severity: 'high' },

  createState() {
    return { win: null, count: 0, max: 0 };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    tally(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    tally(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (dev.win !== win.start) return;
    const count = dev.count;
    dev.win = null;
    dev.count = 0;
    if (ctx.learning) {
      dev.max = Math.max(dev.max, count);
      return;
    }
    const limit = Math.max(ctx.options.minCount, ctx.options.factor * dev.max);
    if (count <= limit) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: win.start,
      actual: `${count} connections/window`,
      expected: `<= ${Math.round(limit)}`,
      data: { count, limit },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { max: dev.max };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.max = typeof state.max === 'number' ? state.max : 0;
    dev.win = null;
    dev.count = 0;
  },

  memoryEstimate() {
    return 16;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function tally(dev, ev, ctx) {
  if (ev.type !== 'flow') return;
  const start = ctx.window && ctx.window.start;
  if (start == null) return;
  if (dev.win !== start) {
    dev.win = start;
    dev.count = 0;
  }
  dev.count += 1;
}

module.exports = detector;
