'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');

const DAY = 24 * 60 * 60 * 1000;
const OPS = new Set(['DESCRIBE', 'SETUP', 'PLAY']);

const detector = {
  id: 'rtsp-new-viewer',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low. NVRs and hubs are learned',
    consumes: ['app', 'flow'],
    attack: ['T1125'],
  },
  requires: ['T5'],
  category: 'app',
  hardRule: false,
  defaults: { severity: 'high' },

  /** @param {any} ev */
  prepare(ev) {
    return clientOf(ev) != null;
  },

  createState() {
    return { clients: new Set(), fired: new Map() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const client = clientOf(ev);
    if (client && dev.clients.size < 64) dev.clients.add(client);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const client = clientOf(ev);
    if (!client || dev.clients.has(client)) return;
    const at = dev.fired.get(client);
    if (typeof at === 'number' && ev.ts - at < DAY) return;
    dev.fired.set(client, ev.ts);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${client} pulled a stream`,
      expected: 'a viewer already in the baseline',
      data: { client },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { clients: [...dev.clients], fired: [...dev.fired.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.clients = new Set();
    dev.fired = new Map();
    if (!state) return;
    if (Array.isArray(state.clients)) {
      if (state.clients.length > 64)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array clients exceeds cap');
      for (const client of state.clients) dev.clients.add(String(client));
    }
    if (Array.isArray(state.fired)) {
      if (state.fired.length > 256)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array fired exceeds cap');
      for (const pair of state.fired) {
        if (Array.isArray(pair)) dev.fired.set(String(pair[0]), Number(pair[1]) || 0);
      }
    }
  },

  memoryEstimate() {
    return 32;
  },
};

/**
 * @param {any} ev
 * @returns {string | null}
 */
function clientOf(ev) {
  if (!ev) return null;
  if (ev.type === 'app' && ev.proto === 'rtsp' && OPS.has(ev.op)) return ev.peerIp;
  if (
    ev.type === 'flow' &&
    ev.direction === 'in' &&
    ev.tcpOutcome === 'established' &&
    (ev.dstPort === 554 || ev.dstPort === 8554)
  ) {
    return ev.srcIp;
  }
  return null;
}

module.exports = detector;
