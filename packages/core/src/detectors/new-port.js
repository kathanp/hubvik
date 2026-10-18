'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');
const { isGroupDst } = require('./lib');

/** @param {any} ev */
function key(ev) {
  if (ev.type !== 'flow' || ev.dstPort == null || ev.direction == null) return null;
  if (isGroupDst(ev.dstIp)) return null;
  return `${ev.direction}:${ev.dstPort}`;
}

const detector = {
  id: 'new-port',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Low for IoT',
  },
  requires: ['T1'],
  category: 'destination',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return {
      ports: new LruSet(Math.min(512, caps.maxDestinations)),
      alerted: new LruSet(caps.maxAlertKeys),
    };
  },

  /** @param {any} dev @param {string} kind @param {string} value */
  allow(dev, kind, value) {
    if (kind !== 'port') return false;
    dev.ports.add(value);
    return true;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const id = key(ev);
    if (id) dev.ports.add(id);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const id = key(ev);
    if (!id || dev.ports.has(id) || dev.alerted.has(id)) return;
    dev.alerted.add(id);
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: id,
      expected: `${dev.ports.size} known ports`,
      data: { port: ev.dstPort, direction: ev.direction },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { ports: dev.ports.toArray(), alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    const max = Math.min(512, caps.maxDestinations);
    dev.ports = fillSet(readStrings(state.ports, max, caps.maxString, 'ports'), max);
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return (dev.ports.size + dev.alerted.size) * 24;
  },
};

module.exports = detector;
