'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'ntp-rogue',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'tunnel',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} ev */
  prepare(ev) {
    return ntp(ev) != null;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const dst = ntp(ev);
    if (dst) dev.seen.add(dst);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const dst = ntp(ev);
    if (!dst || dev.seen.has(dst) || dev.fired.has(dst)) return;
    dev.fired.add(dst);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: dst,
      expected: 'NTP only to a learned server',
      data: { dst },
    };
  },

  exportState: exportSeen,

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },

  memoryEstimate: memorySeen,
};

/**
 * @param {any} ev
 */
function ntp(ev) {
  if (ev.type !== 'flow' || ev.proto !== 'udp' || ev.dstPort !== 123) return null;
  return ev.dstIp;
}

module.exports = detector;
