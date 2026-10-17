'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'ipv6-tunnel',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
    attack: ['T1572'],
  },
  requires: ['T1'],
  category: 'tunnel',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const kind = tunnelKind(ev);
    if (kind) dev.seen.add(kind);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const kind = tunnelKind(ev);
    if (!kind || dev.seen.has(kind) || dev.fired.has(kind)) return;
    dev.fired.add(kind);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: kind,
      expected: 'no IPv6-in-IPv4 tunnel',
      data: { kind },
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
function tunnelKind(ev) {
  if (ev.type !== 'flow') return null;
  if (ev.proto === 41) return '6in4';
  if (ev.proto === 'udp' && ev.dstPort === 3544) return 'teredo';
  return null;
}

module.exports = detector;
