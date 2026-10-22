'use strict';

const { HubvikError } = require('../errors');

const { LruSet } = require('../engine/caps');
const { isPublic } = require('../engine/net');
const { assertState } = require('./state');

const CAP = 256;

const detector = {
  id: 'port-knock',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['flow'],
    attack: ['T1205.001'],
  },
  requires: ['T1'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'high' },

  /** @param {any} ev */
  prepare(ev) {
    return ev.type === 'flow' && ev.direction === 'in' && isPublic(ev.srcIp);
  },

  createState() {
    return { sources: new Map(), seen: new LruSet(CAP) };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'in' || !isPublic(ev.srcIp)) return;
    if (dev.seen.has(ev.srcIp)) return;
    let row = dev.sources.get(ev.srcIp);
    if (!row) {
      if (dev.sources.size >= CAP) {
        const oldest = dev.sources.keys().next().value;
        if (oldest !== undefined) dev.sources.delete(oldest);
      }
      row = { ports: [], at: ev.ts };
      dev.sources.set(ev.srcIp, row);
    }
    const failed = ev.tcpOutcome === 'rejected' || ev.tcpOutcome === 'no-response';
    if (failed) {
      row.ports = row.ports.filter((/** @type {any} */ item) => ev.ts - item.ts <= 10_000);
      if (!row.ports.some((/** @type {any} */ item) => item.port === ev.dstPort)) {
        row.ports.push({ port: ev.dstPort, ts: ev.ts });
      }
      row.at = ev.ts;
      return;
    }
    if (ev.tcpOutcome !== 'established') return;
    const recent = row.ports.filter((/** @type {any} */ item) => ev.ts - item.ts <= 30_000);
    const distinct = new Set(recent.map((/** @type {any} */ item) => item.port));
    if (distinct.size < 3 || distinct.has(ev.dstPort)) return;
    dev.seen.add(ev.srcIp);
    dev.sources.delete(ev.srcIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.srcIp} opened ${ev.dstPort} after ${distinct.size} knocks`,
      expected: 'no hidden listener after a knock sequence',
      data: { srcIp: ev.srcIp, port: ev.dstPort, knocks: [...distinct] },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { seen: dev.seen.toArray() };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.sources = new Map();
    dev.seen = new LruSet(CAP);
    if (!state || !Array.isArray(state.seen)) return;
    if (state.seen.length > CAP)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array seen exceeds cap');
    for (const ip of state.seen) dev.seen.add(String(ip));
  },

  memoryEstimate() {
    return 128;
  },
};

module.exports = detector;
