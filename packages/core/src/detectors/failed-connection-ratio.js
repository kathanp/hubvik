'use strict';

const { SampleRing } = require('../engine/caps');
const { summarize } = require('../engine/math');
const { readSamples } = require('./samples');

const FAIL = new Set(['rejected', 'no-response', 'reset']);

const detector = {
  id: 'failed-connection-ratio',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Low; the most robust scan signal',
    attack: ['T1046'],
  },
  requires: ['T1'],
  category: 'scan',
  defaults: { minAttempts: 20, minRatio: 0.8, sigma: 3, severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return {
      samples: new SampleRing(Math.min(1024, caps.maxWindows)),
      win: null,
      attempts: 0,
      failed: 0,
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    tally(dev, ev, ctx, true);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    tally(dev, ev, ctx, false);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (dev.win !== win.start || dev.attempts === 0) return;
    const ratio = dev.failed / dev.attempts;
    const attempts = dev.attempts;
    dev.attempts = 0;
    dev.failed = 0;
    if (ctx.learning) {
      dev.samples.push(ratio);
      return;
    }
    if (attempts < ctx.options.minAttempts) return;
    const stats = summarize(dev.samples);
    const limit = Math.max(ctx.options.minRatio, stats.mean + ctx.options.sigma * stats.std);
    if (ratio <= limit) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.86,
      ts: win.start,
      actual: `${Math.round(ratio * 100)}% failed (${attempts} attempts)`,
      expected: `<= ${Math.round(limit * 100)}% failed`,
      data: { ratio, attempts, limit },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { samples: dev.samples.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    dev.samples = readSamples(state, { maxWindows: Math.min(1024, caps.maxWindows) }, detector.id);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.samples.length * 8 + 32;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 * @param {boolean} learning
 */
function tally(dev, ev, ctx, learning) {
  if (ev.type !== 'flow' || ev.proto !== 'tcp' || !ev.tcpOutcome) return;
  if (dev.win !== ctx.window.start) {
    dev.win = ctx.window.start;
    dev.attempts = 0;
    dev.failed = 0;
    dev.learning = learning;
  }
  dev.attempts += 1;
  if (FAIL.has(ev.tcpOutcome)) dev.failed += 1;
}

module.exports = detector;
