'use strict';

const { assertState } = require('./state');
const { explainThreshold } = require('./lib');

const WRITE = new Set(['WriteProperty', 'WritePropertyMultiple', 'fc5', 'fc6', 'fc15', 'fc16']);

const detector = {
  id: 'ot-write-rate',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
    explains: true,
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { minWrites: 10, factor: 3, severity: 'high' },

  createState() {
    return { win: null, count: 0, max: 0, fired: false };
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
    dev.count = 0;
    dev.win = null;
    dev.fired = false;
    if (ctx.learning) {
      dev.max = Math.max(dev.max, count);
      return;
    }
    const limit = Math.max(ctx.options.minWrites, ctx.options.factor * dev.max);
    if (count <= limit) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: win.start,
      actual: `${count} writes/window`,
      expected: `<= ${Math.round(limit)}`,
      data: { count, limit },
      explain: explainThreshold({
        test: 'gt',
        observed: count,
        threshold: limit,
        formula: `max(minWrites=${ctx.options.minWrites}, factor=${ctx.options.factor} × learnedMax=${dev.max})`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { max: dev.max };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.max = state && typeof state.max === 'number' ? state.max : 0;
    dev.win = null;
    dev.count = 0;
    dev.fired = false;
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
  if (ev.type !== 'app' || !WRITE.has(ev.op)) return;
  const start = ctx.window && ctx.window.start;
  if (dev.win !== start) {
    dev.win = start;
    dev.count = 0;
    dev.fired = false;
  }
  dev.count += 1;
}

module.exports = detector;
