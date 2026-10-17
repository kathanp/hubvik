'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const WRITE = new Set(['WriteProperty', 'WritePropertyMultiple', 'fc5', 'fc6', 'fc15', 'fc16']);

const detector = {
  id: 'ot-write-new',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const key = writeKey(ev);
    if (key) dev.seen.add(key);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const key = writeKey(ev);
    if (!key || dev.seen.has(key) || dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: key,
      expected: 'writes only to a learned target',
      data: { key },
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
function writeKey(ev) {
  if (ev.type !== 'app' || !WRITE.has(ev.op)) return null;
  return `${ev.peerIp}|${ev.op}|${ev.target || ''}`;
}

module.exports = detector;
