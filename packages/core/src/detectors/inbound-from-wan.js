'use strict';

const { LruSet } = require('../engine/caps');
const { isPublic } = require('../engine/net');
const PORTS = require('../data/ports.json');
const { assertState, readStrings, fillSet } = require('./state');

const HARD = new Set(PORTS.hard);

const detector = {
  id: 'inbound-from-wan',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low; means port forward/UPnP exposure',
    attack: ['T1133'],
  },
  requires: ['T1'],
  category: 'scan',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return {
      outbound: new LruSet(caps.maxDestinations),
      seen: new LruSet(caps.maxAlertKeys),
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow') return;
    if (ev.direction === 'out' && ev.dstIp) {
      dev.outbound.add(ev.dstIp);
      return;
    }
    if (ev.direction !== 'in' || !isPublic(ev.srcIp)) return;
    if (dev.outbound.has(ev.srcIp) || dev.seen.has(ev.srcIp)) return;
    dev.seen.add(ev.srcIp);
    if (ctx.learning && !HARD.has(ev.dstPort)) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${ev.srcIp} -> :${ev.dstPort}`,
      expected: 'no unsolicited inbound from public addresses',
      data: { srcIp: ev.srcIp, dstPort: ev.dstPort },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { outbound: dev.outbound.toArray(), seen: dev.seen.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.outbound = fillSet(
      readStrings(state.outbound, caps.maxDestinations, caps.maxString, 'outbound'),
      caps.maxDestinations,
    );
    dev.seen = fillSet(
      readStrings(state.seen, caps.maxAlertKeys, caps.maxString, 'seen'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return (dev.outbound.size + dev.seen.size) * 32;
  },
};

module.exports = detector;
