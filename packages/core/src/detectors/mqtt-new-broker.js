'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');

/** @param {any} ev */
function broker(ev) {
  if (ev.type !== 'flow' || (ev.dstPort !== 1883 && ev.dstPort !== 8883)) return null;
  return ev.dstName || ev.dstIp || null;
}

const detector = {
  id: 'mqtt-new-broker',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'app',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { brokers: new LruSet(caps.maxDestinations), alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const id = broker(ev);
    if (id) dev.brokers.add(id);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const id = broker(ev);
    if (!id || dev.brokers.has(id) || dev.alerted.has(id)) return;
    dev.alerted.add(id);
    return {
      severity: ctx.options.severity,
      confidence: 0.86,
      ts: ev.ts,
      actual: id,
      expected: `${dev.brokers.size} known MQTT brokers`,
      data: { broker: id, port: ev.dstPort },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { brokers: dev.brokers.toArray(), alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.brokers = fillSet(
      readStrings(state.brokers, caps.maxDestinations, caps.maxString, 'brokers'),
      caps.maxDestinations,
    );
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return (dev.brokers.size + dev.alerted.size) * 32;
  },
};

module.exports = detector;
