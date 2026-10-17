'use strict';

const { SampleRing } = require('../engine/caps');
const { summarize } = require('../engine/math');

/**
 * @param {number} ts
 * @returns {number}
 */
function hourOf(ts) {
  return new Date(ts).getUTCHours();
}

/**
 * @param {any} ring
 * @param {any} options
 */
function limitOf(ring, options) {
  const stats = summarize(ring);
  return Math.max(
    options.minBytes,
    stats.mean + options.sigma * stats.std,
    stats.max * options.peakFactor,
  );
}

const detector = {
  id: 'volume-spike-hourly',
  version: 1,
  meta: {
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
      hours: Array.from({ length: 24 }, () => new SampleRing(size)),
      size,
    };
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    const hour = hourOf(win.start);
    const ring = dev.hours[hour];
    if (ctx.learning) {
      ring.push(win.bytes);
      return;
    }
    if (win.bytes === 0) return;
    const limit = limitOf(ring, ctx.options);
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
    return { hours: dev.hours.map((/** @type {any} */ ring) => ring.toArray()) };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    if (!state || !Array.isArray(state.hours) || state.hours.length !== 24) {
      throw new Error('hours must be 24 arrays');
    }
    const size = Math.max(8, Math.floor(caps.maxWindows / 24));
    dev.size = size;
    dev.hours = state.hours.map((/** @type {any} */ values) => {
      if (!Array.isArray(values) || values.length > size)
        throw new Error('array hours exceeds cap');
      const ring = new SampleRing(size);
      for (const value of values) {
        if (typeof value !== 'number' || value < 0)
          throw new Error('hours must be non-negative numbers');
        ring.push(value);
      }
      return ring;
    });
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.hours.reduce(
      (/** @type {number} */ sum, /** @type {any} */ ring) => sum + ring.length * 8,
      64,
    );
  },
};

module.exports = detector;
