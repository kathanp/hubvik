'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'new-country',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: 'Medium',
  },
  requires: ['T1'],
  category: 'destination',
  defaults: { severity: 'low' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} ev @param {any} ctx */
  prepare(ev, ctx) {
    return lookupCountry(ev, ctx) != null;
  },

  /**
   * @param {any} dev
   * @param {string} kind
   * @param {string} value
   */
  allow(dev, kind, value) {
    if (kind !== 'country') return false;
    dev.seen.add(value);
    return true;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    const country = lookupCountry(ev, ctx);
    if (country) dev.seen.add(country);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const country = lookupCountry(ev, ctx);
    if (!country || dev.seen.has(country) || dev.fired.has(country)) return;
    dev.fired.add(country);
    return {
      severity: ctx.options.severity,
      confidence: 0.6,
      ts: ev.ts,
      actual: country,
      expected: `${dev.seen.size} known countries`,
      data: { country },
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
function lookupCountry(ev, ctx) {
  if (ev.type !== 'flow' || typeof ctx.lookup !== 'function') return null;
  const found = ctx.lookup(ev.dstIp);
  return found && found.country ? found.country : null;
}

module.exports = detector;
