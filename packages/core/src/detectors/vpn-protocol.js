'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'vpn-protocol',
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

  /** @param {any} ev */
  prepare(ev) {
    return vpnKind(ev) != null;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const kind = vpnKind(ev);
    if (kind) dev.seen.add(kind);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const kind = vpnKind(ev);
    if (!kind || dev.seen.has(kind) || dev.fired.has(kind)) return;
    dev.fired.add(kind);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: kind,
      expected: 'no new VPN or SSH protocol',
      data: { kind, port: ev.dstPort },
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
 * @returns {string | null}
 */
function vpnKind(ev) {
  if (ev.type !== 'flow') return null;
  if (ev.proto === 'udp' && ev.dstPort === 51820 && ev.bytesOut === 148) return 'wireguard';
  if (ev.proto === 'udp' && ev.dstPort === 1194) return 'openvpn';
  if (ev.proto === 'udp' && (ev.dstPort === 500 || ev.dstPort === 4500)) return 'ipsec';
  if (ev.proto === 'esp' || ev.proto === 50) return 'esp';
  if (ev.proto === 'tcp' && ev.dstPort === 22) return 'ssh';
  return null;
}

module.exports = detector;
