'use strict';

const { isPublic } = require('../engine/net');
const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const PORTS = new Set([502, 47808, 20000, 44818, 102, 1911, 4911]);

const detector = {
  id: 'ot-wan-exposure',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'ot',
  hardRule: true,
  defaults: { severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || !PORTS.has(ev.dstPort)) return;
    const wan =
      (ev.direction === 'out' && isPublic(ev.dstIp)) ||
      (ev.direction === 'in' && isPublic(ev.srcIp));
    if (!wan) return;
    const key = `${ev.direction}:${ev.dstPort}`;
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.95,
      ts: ev.ts,
      actual: `${ev.direction} OT port ${ev.dstPort}`,
      expected: 'OT protocols stay on the LAN',
      data: { port: ev.dstPort, direction: ev.direction },
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
