'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'fleet-baseline-poisoning',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Medium', consumes: [] },
  requires: ['T0'],
  category: 'fleet',
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return { fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (typeof ev.family !== 'string' || dev.fired.has(ev.family)) return;
    if (dev.fired.size >= 1000) return;
    dev.fired.add(ev.family);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts || 0,
      actual: ev.family,
      expected: 'a family some local peer has learned',
      data: { family: ev.family },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: [...dev.fired].slice(0, 1000) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = new Set(Array.isArray(state.fired) ? state.fired.slice(0, 1000).map(String) : []);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return Math.min(dev.fired.size, 1000) * 20 + 16;
  },
};

module.exports = detector;
