'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');

const detector = {
  id: 'tftp-activity',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: '',
    attack: ['T1071'],
  },
  requires: ['T1'],
  category: 'abuse',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out' || ev.proto !== 'udp' || ev.dstPort !== 69)
      return;
    const key = ev.dstIp || 'unknown';
    if (dev.alerted.has(key)) return;
    dev.alerted.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `tftp ${key}`,
      expected: 'no TFTP toward the WAN',
      data: { dstIp: ev.dstIp || null },
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
