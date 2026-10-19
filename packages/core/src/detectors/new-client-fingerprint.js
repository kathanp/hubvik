'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'new-client-fingerprint',
  version: 1,
  meta: {
    consumes: ['tls'],
    rel: '0.4',
    fpRisk: 'Low on single-purpose IoT, medium after firmware updates',
    attack: ['T1036'],
  },
  requires: ['T3'],
  category: 'tls',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {string} kind @param {string} value */
  allow(dev, kind, value) {
    if (kind !== 'ja4') return false;
    dev.seen.add(value);
    return true;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'tls' && ev.ja4) dev.seen.add(ev.ja4);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'tls' || !ev.ja4 || dev.seen.has(ev.ja4) || dev.fired.has(ev.ja4)) return;
    dev.fired.add(ev.ja4);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: ev.ja4,
      expected: `${dev.seen.size} known client fingerprints`,
      data: { ja4: ev.ja4 },
    };
  },

  exportState: exportSeen,
  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },
  memoryEstimate: memorySeen,
};

module.exports = detector;
