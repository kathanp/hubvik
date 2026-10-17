'use strict';

const { LruSet } = require('../engine/caps');
const { isPublic } = require('../engine/net');
const { assertState, readStrings, fillSet } = require('./state');

const detector = {
  id: 'resolver-bypass',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low on IoT, though some devices hard-code 8.8.8.8, which the baseline absorbs',
  },
  requires: ['T2'],
  category: 'dns',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { resolvers: new LruSet(64), alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {string} kind @param {string} value */
  allow(dev, kind, value) {
    if (kind !== 'resolver') return false;
    dev.resolvers.add(value);
    return true;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'dns' && ev.resolver) dev.resolvers.add(ev.resolver);
    if (ev.type === 'flow' && (ev.dstPort === 53 || ev.dstPort === 853) && ev.dstIp)
      dev.resolvers.add(ev.dstIp);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type === 'dns' && ev.resolver) {
      if (dev.resolvers.has(ev.resolver) || dev.alerted.has(ev.resolver)) return;
      dev.alerted.add(ev.resolver);
      return alert(ctx, ev.ts, ev.resolver, dev.resolvers.size);
    }
    if (ev.type !== 'flow' || (ev.dstPort !== 53 && ev.dstPort !== 853)) return;
    if (!ev.dstIp || !isPublic(ev.dstIp)) return;
    if (dev.resolvers.has(ev.dstIp) || dev.alerted.has(ev.dstIp)) return;
    dev.alerted.add(ev.dstIp);
    return alert(ctx, ev.ts, `${ev.dstIp}:${ev.dstPort}`, dev.resolvers.size);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { resolvers: dev.resolvers.toArray(), alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.resolvers = fillSet(readStrings(state.resolvers, 64, caps.maxString, 'resolvers'), 64);
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return (dev.resolvers.size + dev.alerted.size) * 32;
  },
};

/** @param {any} ctx @param {number} ts @param {string} actual @param {number} known */
function alert(ctx, ts, actual, known) {
  return {
    severity: ctx.options.severity,
    confidence: 0.82,
    ts,
    actual,
    expected: `${known} known resolvers`,
    data: { resolver: actual },
  };
}

module.exports = detector;
