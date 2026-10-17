'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const CLEAR = new Set([21, 23, 80, 1883]);

const detector = {
  id: 'cleartext-regression',
  version: 1,
  meta: {
    consumes: ['flow', 'tls', 'http'],
    rel: '0.4',
    fpRisk: 'Low; downgrade attack or tampered firmware',
    attack: ['T1600'],
  },
  requires: ['T1'],
  category: 'tls',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const dst = secureDst(ev);
    if (dst) dev.seen.add(dst);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const secured = secureDst(ev);
    if (secured) dev.seen.add(secured);
    const dst = clearDst(ev);
    if (!dst || !dev.seen.has(dst) || dev.fired.has(dst)) return;
    dev.fired.add(dst);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `cleartext to ${dst}`,
      expected: 'TLS to a host that used to be encrypted',
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
function secureDst(ev) {
  if (ev.type === 'tls') return ev.sni || ev.dstIp;
  if (ev.type === 'flow' && (ev.dstPort === 443 || ev.dstPort === 8883))
    return ev.dstName || ev.dstIp;
  return null;
}

/**
 * @param {any} ev
 */
function clearDst(ev) {
  if (ev.type === 'http') return ev.host || ev.dstIp;
  if (ev.type === 'flow' && CLEAR.has(ev.dstPort)) return ev.dstName || ev.dstIp;
  return null;
}

module.exports = detector;
