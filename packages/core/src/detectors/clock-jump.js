'use strict';

const { explainChanged, explainThreshold } = require('./lib');

const HOUR = 3600e3;

const detector = {
  id: 'clock-jump',
  version: 1,
  meta: {
    consumes: [
      'summary',
      'flow',
      'dns',
      'tls',
      'http',
      'arp',
      'dhcp',
      'ra',
      'discovery',
      'mapping',
      'app',
    ],
    rel: '0.2',
    fpRisk: '',
    explains: true,
  },
  requires: ['T0'],
  category: 'integrity',
  hardRule: true,
  defaults: { maxForwardMs: 36 * HOUR, severity: 'medium' },

  createState() {
    return { lastTs: null };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ctx.extra && ctx.extra.jump === 'backward') {
      return {
        severity: ctx.options.severity,
        confidence: 0.9,
        ts: ev.ts,
        actual: 'timestamp moved backward',
        expected: 'monotonic timestamps',
        data: { ts: ev.ts },
        explain: explainChanged({ observed: 'backward', previous: 'monotonic' }),
      };
    }
    const previous = dev.lastTs;
    dev.lastTs = ev.ts;
    if (previous == null) return;
    const gap = ev.ts - previous;
    if (gap <= ctx.options.maxForwardMs) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `jumped forward ${Math.round(gap / HOUR)}h`,
      expected: `steps <= ${Math.round(ctx.options.maxForwardMs / HOUR)}h`,
      data: { gapMs: gap },
      explain: explainThreshold({
        test: 'gt',
        observed: gap,
        threshold: ctx.options.maxForwardMs,
        formula: `maxForwardMs=${ctx.options.maxForwardMs}`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { lastTs: dev.lastTs };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    dev.lastTs = state && typeof state.lastTs === 'number' ? state.lastTs : null;
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
