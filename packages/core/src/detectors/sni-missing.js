'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'sni-missing',
  version: 1,
  meta: {
    consumes: ['tls'],
    rel: '0.4',
    fpRisk: 'Medium',
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
    if (ev.type === 'tls' && ev.dstIp) dev.seen.add(ev.dstIp);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'tls' || ev.sni || !ev.dstIp) return;
    if (dev.seen.has(ev.dstIp) || dev.fired.has(ev.dstIp)) return;
    dev.fired.add(ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: ev.dstIp,
      expected: 'TLS to a learned address, or a handshake that carries SNI',
      data: { dstIp: ev.dstIp },
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
