'use strict';

const { assertState } = require('./state');

const HOUR = 3600e3;

const detector = {
  id: 'slow-exfil',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: 'Medium',
    attack: ['T1041'],
    stage: 'impact',
  },
  requires: ['T1'],
  category: 'volume',
  defaults: { minSamples: 6, severity: 'high' },

  createState() {
    return { hour: null, upload: 0, samples: [], cusum: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    roll(dev, ev, false);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    return roll(dev, ev, true, ctx);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { samples: dev.samples.slice(), cusum: dev.cusum, fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    if (state.samples != null && !Array.isArray(state.samples))
      throw new Error('samples must be an array');
    if (state.samples && state.samples.length > 168) throw new Error('array samples exceeds cap');
    dev.samples = Array.isArray(state.samples) ? state.samples.map(Number) : [];
    dev.cusum = typeof state.cusum === 'number' ? state.cusum : 0;
    dev.fired = Boolean(state.fired);
    dev.hour = null;
    dev.upload = 0;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.samples.length * 8 + 24;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} alert
 * @param {any} [ctx]
 */
/**
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} alert
 * @param {any} [ctx]
 */
function roll(dev, ev, alert, ctx) {
  if (ev.type !== 'flow' || ev.direction !== 'out') return;
  const hour = Math.floor(ev.ts / HOUR);
  if (dev.hour == null) dev.hour = hour;
  let closed;
  if (hour !== dev.hour) {
    closed = finishHour(dev, dev.upload, alert, ctx, ev.ts);
    dev.hour = hour;
    dev.upload = 0;
  }
  dev.upload += ev.bytesOut || 0;
  if (closed) return closed;
  if (!alert || !ctx) return;
  return cusum(dev, dev.upload, ctx, ev.ts, false);
}

/**
 * @param {any} dev
 * @param {number} value
 * @param {boolean} alert
 * @param {any} ctx
 * @param {number} ts
 */
function finishHour(dev, value, alert, ctx, ts) {
  if (!alert || !ctx) {
    if (dev.samples.length < 168) dev.samples.push(value);
    return;
  }
  return cusum(dev, value, ctx, ts, true);
}

/**
 * @param {any} dev
 * @param {number} value
 * @param {any} ctx
 * @param {number} ts
 * @param {boolean} commit
 */
function cusum(dev, value, ctx, ts, commit) {
  if (dev.fired || dev.samples.length < ctx.options.minSamples) return;
  let sum = 0;
  for (const sample of dev.samples) sum += sample;
  const mean = sum / dev.samples.length;
  const next = Math.max(0, (commit ? dev.cusum : dev.cusum) + (value - mean - mean));
  if (commit) dev.cusum = next;
  const limit = Math.max(mean * 5, 1e6);
  if (next <= limit) return;
  dev.fired = true;
  dev.cusum = next;
  return {
    severity: ctx.options.severity,
    confidence: 0.75,
    ts,
    actual: `${Math.round(value)} bytes uploaded this hour`,
    expected: `uploads near ${Math.round(mean)} bytes/hour`,
    data: { cusum: dev.cusum, mean, value },
  };
}

module.exports = detector;
