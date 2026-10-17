'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'fleet-wave',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T0'],
  category: 'fleet',
  defaults: { minDevices: 3, windowMs: 600000, severity: 'medium' },

  createState() {
    return { seen: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const dst = ev.dst || ev.dstName || ev.qname;
    if (!dst || dev.seen.has(dst)) return;
    if (dev.seen.size < 5000) dev.seen.add(dst);
    let waves = ctx.scratch.get('fleet-wave');
    if (!waves) {
      waves = new Map();
      ctx.scratch.set('fleet-wave', waves);
    }
    let row = waves.get(dst);
    if (!row || ev.ts - row.first > ctx.options.windowMs) {
      row = { first: ev.ts, devices: new Map(), fired: false };
      waves.set(dst, row);
    }
    row.devices.set(ctx.deviceId, ctx.peerGroup || null);
    if (row.fired || row.devices.size < ctx.options.minDevices) return;
    row.fired = true;
    const groups = [...row.devices.values()];
    const sameGroup = groups[0] != null && groups.every((group) => group === groups[0]);
    return {
      severity: ctx.options.severity,
      confidence: 0.6,
      ts: ev.ts,
      actual: dst,
      expected: 'a new destination that is not spreading across devices',
      data: { dst, peersAffected: row.devices.size, sameGroup },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { seen: [...dev.seen].slice(0, 5000) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.seen = new Set(Array.isArray(state.seen) ? state.seen.slice(0, 5000) : []);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.seen.size * 24 + 16;
  },
};

module.exports = detector;
