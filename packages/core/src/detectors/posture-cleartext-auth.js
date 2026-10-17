'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const PORTS = new Set([21, 23]);

const detector = {
  id: 'posture-cleartext-auth',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'posture',
  defaults: { severity: 'low' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.proto !== 'tcp') return;
    const port = PORTS.has(ev.dstPort) ? ev.dstPort : PORTS.has(ev.srcPort) ? ev.srcPort : 0;
    if (!port) return;
    const key = String(port);
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `cleartext auth on port ${port}`,
      expected: 'authenticated sessions over TLS',
      data: { port },
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
