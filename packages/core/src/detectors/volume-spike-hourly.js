'use strict';

const { emptyStats, pushSample, statsOf } = require('../engine/math');
const { readStreamState } = require('./samples');

/**
 * @param {number} ts
 * @returns {number}
 */
function hourOf(ts) {
  return new Date(ts).getUTCHours();
}

/**
 * @param {any} stats
 * @param {any} options
 */
function limitOf(stats, options) {
  const summary = statsOf(stats);
  return Math.max(
    options.minBytes,
    summary.mean + options.sigma * summary.std,
    summary.max * options.peakFactor,
  );
}

const detector = {
  id: 'volume-spike-hourly',
  version: 1,
  meta: {
    consumes: [],
    rel: '0.2',
    fpRisk: 'Lower than flat baseline',
    attack: ['T1498'],
    stage: 'impact',
  },
  requires: ['T0'],
  category: 'volume',
  defaults: { sigma: 4, minBytes: 1_000_000, peakFactor: 2, severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    const size = Math.max(8, Math.floor(caps.maxWindows / 24));
    return {
      hours: Array.from({ length: 24 }, () => emptyStats()),
      size,
    };
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    const hour = hourOf(win.start);
    const stats = dev.hours[hour];
    if (ctx.learning) {
      pushSample(stats, win.bytes);
      return;
    }
    if (win.bytes === 0) return;
    const limit = limitOf(stats, ctx.options);
    if (win.bytes <= limit) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.84,
      ts: win.start,
      actual: `${win.bytes} bytes at hour ${hour}`,
      expected: `<= ${Math.round(limit)} bytes at hour ${hour}`,
      data: { bytes: win.bytes, hour, limit },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      hours: dev.hours.map((/** @type {any} */ stats) => ({
        count: stats.count,
        mean: stats.mean,
        m2: stats.m2,
        max: stats.max,
      })),
    };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    if (!state || !Array.isArray(state.hours) || state.hours.length !== 24) {
      throw new Error('hours must be 24 arrays');
    }
    const size = Math.max(8, Math.floor(caps.maxWindows / 24));
    dev.size = size;
    dev.hours = state.hours.map((/** @type {any} */ hour) => {
      if (Array.isArray(hour)) {
        if (hour.length > size) throw new Error('array hours exceeds cap');
        return readStreamState({ samples: hour }, size, detector.id);
      }
      return readStreamState(hour, size, detector.id);
    });
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    if (!Array.isArray(dev.hours)) return 64;
    return 64 + dev.hours.length * 48;
  },
};

module.exports = detector;
