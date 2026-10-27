'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'quic-new',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.4',
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
    return quic(ev) != null;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const dst = quic(ev);
    if (dst) dev.seen.add(dst);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const dst = quic(ev);
    if (!dst || dev.seen.has(dst) || dev.fired.has(dst)) return;
    dev.fired.add(dst);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: dst,
      expected: 'no new QUIC peer',
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
function quic(ev) {
  if (ev.type !== 'flow' || ev.proto !== 'udp' || ev.dstPort !== 443) return null;
  return ev.dstName || ev.dstIp;
}

module.exports = detector;
