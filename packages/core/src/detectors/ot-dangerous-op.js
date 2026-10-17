'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const DANGER = new Set([
  'ReinitializeDevice',
  'DeviceCommunicationControl',
  'AtomicWriteFile',
  'fc8',
  'STOP',
  'download',
]);

const detector = {
  id: 'ot-dangerous-op',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
    attack: ['T1565'],
    stage: 'impact',
  },
  requires: ['T5'],
  category: 'ot',
  hardRule: true,
  defaults: { severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || !DANGER.has(ev.op)) return;
    const key = `${ev.peerIp}|${ev.op}|${ev.target || ''}`;
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.95,
      ts: ev.ts,
      actual: ev.op,
      expected: 'no program, stop, or silence command',
      data: { op: ev.op, peerIp: ev.peerIp, target: ev.target || null },
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
