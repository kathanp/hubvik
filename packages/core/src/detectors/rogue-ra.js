'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'rogue-ra',
  version: 1,
  meta: {
    consumes: ['ra'],
    rel: '0.3',
    fpRisk: 'Very low',
  },
  requires: ['T4'],
  category: 'link',
  hardRule: true,
  defaults: { severity: 'critical' },

  createState() {
    return { router: null, fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'ra' || !ev.srcIp) return;
    const allowed = ctx.routers || [];
    if (allowed.length > 0) {
      if (allowed.includes(ev.srcIp) || dev.fired.has(ev.srcIp)) return;
      dev.fired.add(ev.srcIp);
      return draft(ctx, ev, allowed.join(','));
    }
    if (!dev.router) {
      dev.router = ev.srcIp;
      return;
    }
    if (dev.router === ev.srcIp || dev.fired.has(ev.srcIp)) return;
    dev.fired.add(ev.srcIp);
    return draft(ctx, ev, dev.router);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { router: dev.router };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.router = state && typeof state.router === 'string' ? state.router : null;
    dev.fired = new Set();
  },

  memoryEstimate() {
    return 24;
  },
};

/**
 * @param {any} ctx
 * @param {any} ev
 * @param {string} expected
 */
function draft(ctx, ev, expected) {
  return {
    severity: ctx.options.severity,
    confidence: 0.95,
    ts: ev.ts,
    actual: ev.srcIp,
    expected: `router advertisements from ${expected}`,
    data: { srcIp: ev.srcIp, srcMac: ev.srcMac },
  };
}

module.exports = detector;
