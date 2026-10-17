'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'new-asn',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Medium',
  },
  requires: ['T1'],
  category: 'destination',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /**
   * @param {any} dev
   * @param {string} kind
   * @param {string} value
   */
  allow(dev, kind, value) {
    if (kind !== 'asn') return false;
    dev.seen.add(value);
    return true;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    const asn = lookupAsn(ev, ctx);
    if (asn) dev.seen.add(asn);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const asn = lookupAsn(ev, ctx);
    if (!asn || dev.seen.has(asn) || dev.fired.has(asn)) return;
    dev.fired.add(asn);
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: asn,
      expected: `${dev.seen.size} known networks`,
      data: { asn },
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
 * @param {any} ctx
 * @returns {string | null}
 */
function lookupAsn(ev, ctx) {
  if (ev.type !== 'flow' || typeof ctx.lookup !== 'function') return null;
  const found = ctx.lookup(ev.dstIp);
  return found && found.asn ? found.asn : null;
}

module.exports = detector;
