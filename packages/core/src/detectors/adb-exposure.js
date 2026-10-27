'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');
const { explainMatch } = require('./lib');

const detector = {
  id: 'adb-exposure',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: '',
    attack: ['T1021'],
    stage: 'spread',
    explains: true,
  },
  requires: ['T1'],
  category: 'app',
  hardRule: true,
  defaults: { severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} ev */
  prepare(ev) {
    return (
      ev.type === 'flow' && ev.proto === 'tcp' && ev.dstPort === 5555 && ev.direction !== 'out'
    );
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.proto !== 'tcp' || ev.dstPort !== 5555) return;
    if (ev.direction === 'out') return;
    const key = ev.srcIp || 'unknown';
    if (dev.alerted.has(key)) return;
    dev.alerted.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.95,
      ts: ev.ts,
      actual: `${key} -> :5555`,
      expected: 'no connections to ADB',
      data: { srcIp: ev.srcIp || null, direction: ev.direction },
      explain: explainMatch({ observed: `${key} -> :5555`, matched: 5555, source: 'dstPort' }),
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
