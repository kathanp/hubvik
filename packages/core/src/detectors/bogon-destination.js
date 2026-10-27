'use strict';

const { LruSet } = require('../engine/caps');
const { isBogon } = require('../engine/net');
const { assertState, readStrings, fillSet } = require('./state');

const detector = {
  id: 'bogon-destination',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Low',
  },
  requires: ['T1'],
  category: 'destination',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} ev */
  prepare(ev) {
    return ev.type === 'flow' && ev.direction === 'out' && isBogon(ev.dstIp);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out' || !isBogon(ev.dstIp)) return;
    if (dev.alerted.has(ev.dstIp)) return;
    dev.alerted.add(ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: ev.dstIp,
      expected: 'a globally routable destination',
      data: { dstIp: ev.dstIp },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.alerted.size * 32;
  },
};

module.exports = detector;
