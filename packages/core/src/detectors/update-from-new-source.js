'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'update-from-new-source',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'supply',
  defaults: { minBytes: 5000000, severity: 'high' },

  /**
   * @param {any} caps
   * @returns {any}
   */
  createState(caps) {
    /** @type {any} */
    const state = seenState(caps);
    state.sizes = [];
    return state;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type !== 'flow' || ev.direction !== 'in') return;
    const dst = ev.dstName || ev.srcIp;
    if (dst) dev.seen.add(dst);
    if (dev.sizes.length < 64) dev.sizes.push(ev.bytesIn || 0);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'in') return;
    const dst = ev.dstName || ev.srcIp;
    if (!dst || dev.seen.has(dst) || dev.fired.has(dst)) return;
    const limit = Math.max(ctx.options.minBytes, percentile(dev.sizes));
    if ((ev.bytesIn || 0) <= limit) return;
    dev.fired.add(dst);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${ev.bytesIn} bytes from ${dst}`,
      expected: `downloads <= ${Math.round(limit)} from a known host`,
      data: { dst, bytesIn: ev.bytesIn },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { ...exportSeen(dev), sizes: dev.sizes.slice() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
    dev.sizes = state && Array.isArray(state.sizes) ? state.sizes.slice(0, 64).map(Number) : [];
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return memorySeen(dev) + dev.sizes.length * 8;
  },
};

/**
 * @param {number[]} values
 */
function percentile(values) {
  if (values.length === 0) return 0;
  const sorted = values.slice().sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(0.99 * (sorted.length - 1)))];
}

module.exports = detector;
