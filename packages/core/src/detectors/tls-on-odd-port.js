'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'tls-on-odd-port',
  version: 1,
  meta: {
    consumes: ['tls'],
    rel: '0.4',
    fpRisk: 'Low',
  },
  requires: ['T3'],
  category: 'tls',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'tls') dev.seen.add(String(ev.dstPort));
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'tls') return;
    const key = String(ev.dstPort);
    if (dev.seen.has(key) || dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: `TLS on port ${key}`,
      expected: 'TLS only on a learned port',
      data: { port: ev.dstPort },
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
