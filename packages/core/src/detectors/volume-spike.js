'use strict';

const { emptyStats, pushSample, statsOf } = require('../engine/math');
const { readStreamState } = require('./samples');

const detector = {
  id: 'volume-spike',
  version: 1,
  meta: {
    consumes: [],
    rel: '0.1',
    fpRisk: 'Medium for cameras',
    attack: ['T1498'],
    stage: 'impact',
  },
  requires: ['T0'],
  category: 'volume',
  defaults: { sigma: 4, minBytes: 1_000_000, peakFactor: 2, severity: 'high' },

  createState() {
    return { stats: emptyStats(), cachedLimit: null };
  },

  learn() {},

  /**
   * @param {{ stats: { count: number, mean: number, m2: number, max: number }, cachedLimit: number | null }} dev
   * @param {{ bytes: number, start: number }} win
   * @param {{ learning: boolean, options: { sigma: number, minBytes: number, peakFactor: number, severity: string } }} ctx
   */
  onWindowClose(dev, win, ctx) {
    if (ctx.learning) {
      pushSample(dev.stats, win.bytes);
      dev.cachedLimit = null;
      return;
    }
    if (win.bytes === 0) return;
    const limit = cachedLimit(dev, ctx.options);
    if (win.bytes > limit) {
      return {
        severity: ctx.options.severity,
        confidence: 0.85,
        ts: win.start,
        actual: `${win.bytes} bytes/window`,
        expected: `<= ${Math.round(limit)}`,
        data: { bytes: win.bytes, limit },
        attack: ['T1498'],
      };
    }
  },

  /** @param {{ stats: { count: number, mean: number, m2: number, max: number } }} dev */
  exportState(dev) {
    return {
      count: dev.stats.count,
      mean: dev.stats.mean,
      m2: dev.stats.m2,
      max: dev.stats.max,
    };
  },

  /**
   * @param {{ stats: any, cachedLimit: number | null }} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    dev.stats = readStreamState(state, caps.maxWindows, 'volume-spike');
    dev.cachedLimit = null;
  },

  memoryEstimate() {
    return 64;
  },
};

/**
 * @param {{ stats: { count: number, mean: number, m2: number, max: number }, cachedLimit: number | null }} dev
 * @param {{ sigma: number, minBytes: number, peakFactor: number }} options
 */
function cachedLimit(dev, options) {
  if (dev.cachedLimit == null) {
    const stats = statsOf(dev.stats);
    dev.cachedLimit = Math.max(
      options.minBytes,
      stats.mean + options.sigma * stats.std,
      stats.max * options.peakFactor,
    );
  }
  return dev.cachedLimit;
}

module.exports = detector;
