'use strict';

const { scratchBag } = require('./lib');

const detector = {
  id: 'ra-flood',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['ra'],
    attack: ['T1498'],
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return {};
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'ra' || !ev.srcMac) return;
    const start = ctx.window && ctx.window.start;
    const bag = scratchBag(ctx, 'ra-flood', () => ({
      win: start,
      count: 0,
      macs: new Map(),
      pairs: new Set(),
      fired: false,
    }));
    if (bag.win !== start) {
      bag.win = start;
      bag.count = 0;
      bag.macs = new Map();
      bag.pairs = new Set();
      bag.fired = false;
    }
    const count = Number.isInteger(ev.count) ? ev.count : 1;
    bag.count += count;
    bag.macs.set(ev.srcMac, (bag.macs.get(ev.srcMac) || 0) + count);
    const prefixes = Array.isArray(ev.prefixes) && ev.prefixes.length > 0 ? ev.prefixes : [''];
    for (const prefix of prefixes) {
      if (bag.pairs.size < 5000) bag.pairs.add(`${ev.srcMac}|${prefix}`);
    }
    if (bag.fired || (bag.count < 50 && bag.pairs.size < 20)) return;
    bag.fired = true;
    const top = [...bag.macs.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3)
      .map((pair) => pair[0]);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${bag.count} router advertisements`,
      expected: '< 50 advertisements and < 20 source pairs per window',
      data: { count: bag.count, pairs: bag.pairs.size, macs: top },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    if (state && typeof state !== 'object') return;
  },

  memoryEstimate() {
    return 8;
  },
};

module.exports = detector;
