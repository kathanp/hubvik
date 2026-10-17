'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'long-connection',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: 'Low',
  },
  requires: ['T1'],
  category: 'timing',
  defaults: { minDurationMs: 600000, severity: 'high' },

  /**
   * @param {any} caps
   * @returns {any}
   */
  createState(caps) {
    /** @type {any} */
    const state = seenState(caps);
    state.durations = [];
    return state;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type !== 'flow') return;
    const dst = ev.dstName || ev.dstIp;
    if (dst) dev.seen.add(dst);
    if (dev.durations.length < 64 && ev.durationMs > 0) dev.durations.push(ev.durationMs);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out') return;
    const dst = ev.dstName || ev.dstIp;
    if (!dst || dev.seen.has(dst) || dev.fired.has(dst)) return;
    const limit = Math.max(ctx.options.minDurationMs, percentile(dev.durations, 0.99));
    if (ev.durationMs <= limit) return;
    dev.fired.add(dst);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${dst} for ${Math.round(ev.durationMs / 1000)}s`,
      expected: `sessions <= ${Math.round(limit / 1000)}s to a known host`,
      data: { dst, durationMs: ev.durationMs, limit },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { ...exportSeen(dev), durations: dev.durations.slice() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
    dev.durations =
      state && Array.isArray(state.durations) ? state.durations.slice(0, 64).map(Number) : [];
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return memorySeen(dev) + dev.durations.length * 8;
  },
};

/**
 * @param {number[]} values
 * @param {number} p
 */
function percentile(values, p) {
  if (values.length === 0) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.floor(p * (sorted.length - 1)));
  return sorted[index];
}

module.exports = detector;
