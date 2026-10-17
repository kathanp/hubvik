'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');

/** @param {any} ev */
function proto(ev) {
  if (ev.type !== 'flow' || ev.proto == null) return null;
  return String(ev.proto);
}

const detector = {
  id: 'new-protocol',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Very low; GRE from a camera is Mirai GREIP/GREETH territory',
  },
  requires: ['T1'],
  category: 'destination',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { protos: new LruSet(64), alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const id = proto(ev);
    if (id) dev.protos.add(id);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const id = proto(ev);
    if (!id || dev.protos.has(id) || dev.alerted.has(id)) return;
    dev.alerted.add(id);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: id,
      expected: [...dev.protos.toArray()].join(',') || 'none',
      data: { proto: id },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { protos: dev.protos.toArray(), alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.protos = fillSet(readStrings(state.protos, 64, caps.maxString, 'protos'), 64);
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.protos.size * 16 + 32;
  },
};

module.exports = detector;
