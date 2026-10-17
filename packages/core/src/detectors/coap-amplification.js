'use strict';

const { LruSet } = require('../engine/caps');
const { isPublic } = require('../engine/net');
const { assertState, readStrings, fillSet } = require('./state');

const detector = {
  id: 'coap-amplification',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: '',
    attack: ['T1498'],
    stage: 'impact',
    dedupGroup: 'reflection',
  },
  requires: ['T1'],
  category: 'volume',
  hardRule: true,
  defaults: { minRatio: 3, minBytes: 300, severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out' || ev.proto !== 'udp' || ev.srcPort !== 5683)
      return;
    if (!isPublic(ev.dstIp)) return;
    const out = ev.bytesOut || 0;
    const inn = ev.bytesIn || 0;
    if (out < ctx.options.minBytes) return;
    if (inn > 0 && out / inn <= ctx.options.minRatio) return;
    if (dev.alerted.has(ev.dstIp)) return;
    dev.alerted.add(ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.93,
      ts: ev.ts,
      actual: `coap reply to ${ev.dstIp}`,
      expected: 'no large CoAP replies toward the public internet',
      data: { dstIp: ev.dstIp, bytesOut: out, bytesIn: inn },
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
