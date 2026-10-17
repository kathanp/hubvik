'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'ot-new-master',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
    attack: ['T0867'],
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'app' && ev.peerIp) dev.seen.add(ev.peerIp);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || !ev.peerIp || dev.seen.has(ev.peerIp) || dev.fired.has(ev.peerIp))
      return;
    dev.fired.add(ev.peerIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: ev.peerIp,
      expected: 'only a learned master or client',
      data: { peerIp: ev.peerIp, op: ev.op },
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
