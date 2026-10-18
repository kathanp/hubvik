'use strict';

const { LruSet } = require('../engine/caps');
const PORTS = require('../data/ports.json');
const { assertState, readStrings, fillSet } = require('./state');
const { isGroupDst } = require('./lib');

const LISTEN = new Set(PORTS.listen);

const detector = {
  id: 'posture-listening-risky',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'posture',
  defaults: { severity: 'low' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || !LISTEN.has(ev.dstPort) || isGroupDst(ev.dstIp)) return;
    const responder =
      ev.direction === 'in' || (ev.direction === 'lan' && ev.dstIp === ctx.deviceId);
    if (!responder) return;
    const key = String(ev.dstPort);
    if (dev.alerted.has(key)) return;
    dev.alerted.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `accepts tcp/${ev.dstPort}`,
      expected: 'no listening risky service',
      data: { port: ev.dstPort, direction: ev.direction },
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
    return dev.alerted.size * 16;
  },
};

module.exports = detector;
