'use strict';

const { SampleRing } = require('../engine/caps');
const { summarize } = require('../engine/math');
const { readSamples } = require('./samples');

const detector = {
  id: 'nxdomain-burst',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low',
    attack: ['T1568'],
  },
  requires: ['T2'],
  category: 'dns',
  defaults: { minCount: 10, factor: 3, severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { samples: new SampleRing(Math.min(1024, caps.maxWindows)), win: null, count: 0 };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    count(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    count(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (dev.win !== win.start) return;
    const value = dev.count;
    dev.count = 0;
    if (ctx.learning) {
      dev.samples.push(value);
      return;
    }
    const stats = summarize(dev.samples);
    const limit = Math.max(ctx.options.minCount, ctx.options.factor * stats.max);
    if (value <= limit) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: win.start,
      actual: `${value} NXDOMAIN answers`,
      expected: `<= ${limit} NXDOMAIN answers/window`,
      data: { count: value, limit },
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

/** @param {any} dev @param {any} ev @param {any} ctx */
function count(dev, ev, ctx) {
  if (ev.type !== 'dns' || String(ev.rcode).toUpperCase() !== 'NXDOMAIN') return;
  if (dev.win !== ctx.window.start) {
    dev.win = ctx.window.start;
    dev.count = 0;
  }
  dev.count += 1;
}

module.exports = detector;
