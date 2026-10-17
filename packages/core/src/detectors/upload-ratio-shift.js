'use strict';

const { SampleRing } = require('../engine/caps');
const { summarize } = require('../engine/math');
const { readSamples } = require('./samples');

const detector = {
  id: 'upload-ratio-shift',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low',
  },
  requires: ['T1'],
  category: 'volume',
  defaults: { minBytes: 10_000, shift: 0.35, severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { samples: new SampleRing(Math.min(2048, caps.maxWindows)), win: null, out: 0, inn: 0 };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    add(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    add(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (dev.win !== win.start) return;
    const total = dev.out + dev.inn;
    const ratio = total === 0 ? 0 : dev.out / total;
    dev.out = 0;
    dev.inn = 0;
    if (ctx.learning) {
      if (total > 0) dev.samples.push(ratio);
      return;
    }
    if (total < ctx.options.minBytes || dev.samples.length < 5) return;
    const stats = summarize(dev.samples);
    const limit = Math.min(1, stats.max + ctx.options.shift);
    if (ratio <= limit) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: win.start,
      actual: `${Math.round(ratio * 100)}% upload`,
      expected: `<= ${Math.round(limit * 100)}% upload`,
      data: { ratio, limit, bytes: total },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { samples: dev.samples.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    dev.samples = readSamples(state, { maxWindows: Math.min(2048, caps.maxWindows) }, detector.id);
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
 */
function add(dev, ev, ctx) {
  if (ev.type !== 'flow') return;
  if (dev.win !== ctx.window.start) {
    dev.win = ctx.window.start;
    dev.out = 0;
    dev.inn = 0;
  }
  dev.out += ev.bytesOut || 0;
  dev.inn += ev.bytesIn || 0;
}

module.exports = detector;
