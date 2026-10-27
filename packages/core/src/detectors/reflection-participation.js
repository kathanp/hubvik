'use strict';

const { LruSet } = require('../engine/caps');
const { isPublic } = require('../engine/net');
const PORTS = require('../data/ports.json');
const { assertState, readStrings, fillSet } = require('./state');
const { explainThreshold } = require('./lib');

const REFLECT = new Set(PORTS.reflection);

const detector = {
  id: 'reflection-participation',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Very low',
    attack: ['T1498'],
    explains: true,
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

  /** @param {any} ev */
  prepare(ev) {
    return (
      ev.type === 'flow' &&
      ev.direction === 'out' &&
      ev.proto === 'udp' &&
      REFLECT.has(ev.srcPort) &&
      isPublic(ev.dstIp)
    );
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out' || ev.proto !== 'udp') return;
    if (!REFLECT.has(ev.srcPort) || !isPublic(ev.dstIp)) return;
    const out = ev.bytesOut || 0;
    const inn = ev.bytesIn || 0;
    if (out < ctx.options.minBytes) return;
    if (inn > 0 && out / inn <= ctx.options.minRatio) return;
    const key = `${ev.srcPort}|${ev.dstIp}`;
    if (dev.alerted.has(key)) return;
    dev.alerted.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.93,
      ts: ev.ts,
      actual: `udp/${ev.srcPort} to ${ev.dstIp}`,
      expected: 'no amplified replies from a reflection port toward the public internet',
      data: { srcPort: ev.srcPort, dstIp: ev.dstIp, bytesOut: out, bytesIn: inn },
      explain: explainThreshold({
        test: 'gte',
        observed: out,
        threshold: ctx.options.minBytes,
        formula: `minBytes=${ctx.options.minBytes}`,
      }),
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
    return dev.alerted.size * 40;
  },
};

module.exports = detector;
