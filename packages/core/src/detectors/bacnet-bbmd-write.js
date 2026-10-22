'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');

const OPS = new Set(['Write-Broadcast-Distribution-Table', 'Register-Foreign-Device']);

const detector = {
  id: 'bacnet-bbmd-write',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Very low',
    consumes: ['app'],
    attack: ['T0836'],
  },
  requires: ['T5'],
  category: 'ot',
  hardRule: false,
  defaults: { severity: 'critical' },

  createState() {
    return { clients: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'app' && ev.proto === 'bacnet' && OPS.has(ev.op) && dev.clients.size < 64) {
      dev.clients.add(ev.peerIp);
    }
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || ev.proto !== 'bacnet' || !OPS.has(ev.op)) return;
    if (dev.clients.has(ev.peerIp)) return;
    dev.clients.add(ev.peerIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.95,
      ts: ev.ts,
      actual: `${ev.peerIp} ${ev.op}`,
      expected: 'a BACnet client already in the learned set',
      data: { peerIp: ev.peerIp, op: ev.op },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { clients: [...dev.clients] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.clients = new Set();
    if (!state || !Array.isArray(state.clients)) return;
    if (state.clients.length > 64)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array clients exceeds cap');
    for (const ip of state.clients) dev.clients.add(String(ip));
  },

  memoryEstimate() {
    return 32;
  },
};

module.exports = detector;
