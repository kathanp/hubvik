'use strict';

const PORTS = require('../data/ports.json');
const { assertState } = require('./state');

const HARD = new Set(PORTS.hard);

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function slot(dev, ev, ctx) {
  const start = ctx.window.start;
  if (dev.win !== start) {
    if (dev.learning && dev.counts) {
      for (const [port, count] of dev.counts) {
        dev.max.set(port, Math.max(dev.max.get(port) || 0, count));
      }
    }
    dev.win = start;
    dev.learning = ctx.learning;
    dev.counts = new Map();
    dev.seen = new Set();
    dev.fired = new Set();
  }
}

const detector = {
  id: 'horizontal-scan',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Very low',
    attack: ['T1046'],
    stage: 'spread',
  },
  requires: ['T1'],
  category: 'scan',
  hardRule: true,
  defaults: { minHosts: 20, minHardHosts: 10, factor: 3, severity: 'critical' },

  createState() {
    return {
      max: new Map(),
      win: null,
      learning: false,
      counts: new Map(),
      seen: new Set(),
      fired: new Set(),
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.dstPort == null || !ev.dstIp) return;
    slot(dev, ev, ctx);
    const id = `${ev.dstPort}|${ev.dstIp}`;
    if (dev.seen.has(id)) return;
    if (dev.seen.size >= 5000) return;
    dev.seen.add(id);
    const count = (dev.counts.get(ev.dstPort) || 0) + 1;
    dev.counts.set(ev.dstPort, count);
    if (dev.fired.has(ev.dstPort)) return;
    const learned = dev.max.get(ev.dstPort) || 0;
    const hard = ctx.learning && HARD.has(ev.dstPort);
    if (ctx.learning && !hard) return;
    const limit = hard
      ? ctx.options.minHardHosts
      : Math.max(ctx.options.minHosts, ctx.options.factor * learned);
    if (count <= limit) return;
    dev.fired.add(ev.dstPort);
    return {
      severity: ctx.options.severity,
      confidence: 0.92,
      ts: ev.ts,
      actual: `${count} hosts on port ${ev.dstPort}`,
      expected: `<= ${limit} hosts/window`,
      data: { dstPort: ev.dstPort, hosts: count, limit },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { max: [...dev.max.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.max = new Map();
    if (!Array.isArray(state.max)) throw new Error('max must be an array');
    if (state.max.length > 512) throw new Error('array max exceeds cap');
    for (const pair of state.max) {
      if (!Array.isArray(pair) || pair.length !== 2) throw new Error('max entries are invalid');
      const [port, count] = pair;
      if (!Number.isInteger(port) || typeof count !== 'number')
        throw new Error('max entries are invalid');
      dev.max.set(port, count);
    }
    dev.win = null;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.max.size * 16 + dev.seen.size * 32;
  },
};

module.exports = detector;
