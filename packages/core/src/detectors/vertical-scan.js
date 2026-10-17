'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'vertical-scan',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low',
    attack: ['T1046'],
    stage: 'recon',
  },
  requires: ['T1'],
  category: 'scan',
  defaults: { minPorts: 15, factor: 3, severity: 'high' },

  createState() {
    return {
      max: 0,
      win: null,
      learning: false,
      counts: new Map(),
      seen: new Set(),
      fired: new Set(),
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    record(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const count = record(dev, ev, ctx);
    if (count == null || dev.fired.has(ev.dstIp)) return;
    const limit = Math.max(ctx.options.minPorts, ctx.options.factor * dev.max);
    if (count <= limit) return;
    dev.fired.add(ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${count} ports on ${ev.dstIp}`,
      expected: `<= ${limit} ports/window`,
      data: { dstIp: ev.dstIp, ports: count, limit },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { max: dev.max };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    if (typeof state.max !== 'number' || state.max < 0) throw new Error('max must be a number');
    dev.max = state.max;
    dev.win = null;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return 64 + dev.seen.size * 24;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 * @returns {number | null}
 */
function record(dev, ev, ctx) {
  if (ev.type !== 'flow' || !ev.dstIp || ev.dstPort == null) return null;
  if (dev.win !== ctx.window.start) {
    if (dev.learning) {
      for (const count of dev.counts.values()) dev.max = Math.max(dev.max, count);
    }
    dev.win = ctx.window.start;
    dev.learning = ctx.learning;
    dev.counts = new Map();
    dev.seen = new Set();
    dev.fired = new Set();
  }
  const id = `${ev.dstIp}|${ev.dstPort}`;
  if (dev.seen.has(id) || dev.seen.size >= 5000) return dev.counts.get(ev.dstIp) || 0;
  dev.seen.add(id);
  const count = (dev.counts.get(ev.dstIp) || 0) + 1;
  dev.counts.set(ev.dstIp, count);
  return count;
}

module.exports = detector;
