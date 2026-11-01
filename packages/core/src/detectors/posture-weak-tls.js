'use strict';

const { seenState, exportSeen, importSeen, memorySeen, explainMatch } = require('./lib');

const WEAK = new Set(['TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2']);

const detector = {
  id: 'posture-weak-tls',
  version: 1,
  meta: {
    consumes: ['tls'],
    rel: '0.4',
    fpRisk: '',
    explains: true,
  },
  requires: ['T3'],
  category: 'posture',
  defaults: { severity: 'low' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'tls') return;
    const reason = weak(ev);
    if (!reason) return;
    const key = `${ev.dstIp}:${reason}`;
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: reason,
      expected: 'TLS 1.2 or newer, with a currently valid certificate',
      data: { dstIp: ev.dstIp, reason },
      explain: explainMatch({ observed: reason, matched: reason, source: 'tls' }),
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
function weak(ev) {
  if (WEAK.has(ev.version)) return ev.version;
  if (ev.cert && ev.cert.selfSigned) return 'self-signed';
  if (ev.cert && typeof ev.cert.notAfter === 'number' && ev.cert.notAfter < ev.ts) return 'expired';
  return null;
}

module.exports = detector;
