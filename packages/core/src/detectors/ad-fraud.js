'use strict';

const { exactHit } = require('../engine/indicators');
const { assertState } = require('./state');

const detector = {
  id: 'ad-fraud',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T2'],
  category: 'monetization',
  defaults: { minDomains: 5, severity: 'medium' },

  createState() {
    return { win: null, names: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !ev.qname) return;
    const hit = adHit(ctx.indicatorIndex, ev.qname, ev.ts);
    if (!hit) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.names = new Set();
      dev.fired = false;
    }
    if (dev.names.size < 64) dev.names.add(ev.qname);
    if (dev.fired || dev.names.size < ctx.options.minDomains) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `${dev.names.size} ad domains`,
      expected: `< ${ctx.options.minDomains} ad or tracker names per window`,
      data: { names: [...dev.names] },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.names = new Set();
    dev.fired = false;
  },

  memoryEstimate() {
    return 32;
  },
};

/**
 * @param {any} index
 * @param {string} name
 * @param {number} ts
 */
function adHit(index, name, ts) {
  if (!index) return null;
  const labels = name.toLowerCase().split('.').filter(Boolean);
  for (let i = 0; i < labels.length; i++) {
    const hit = exactHit(index, 'ad', labels.slice(i).join('.'), ts);
    if (hit) return hit;
  }
  return null;
}

module.exports = detector;
