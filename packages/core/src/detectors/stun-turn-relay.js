'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const HOUR = 60 * 60 * 1000;
const FIVE_MB = 5 * 1024 * 1024;

/**
 * @param {any} ev
 * @returns {boolean}
 */
function relay(ev) {
  if (ev.dstPort === 3478 || ev.dstPort === 5349) return true;
  const name = ev.dstName || ev.dst || '';
  const label = String(name).split('.')[0];
  return label === 'stun' || label === 'turn';
}

const detector = {
  id: 'stun-turn-relay',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Medium: video doorbells use WebRTC. The baseline absorbs their relays',
    consumes: ['flow'],
    attack: ['T1090'],
  },
  requires: ['T1'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'medium' },

  /** @param {any} ev */
  prepare(ev) {
    return ev.type === 'flow' && relay(ev);
  },

  createState() {
    return { hosts: new Set(), bytes: new Map(), fired: false };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type !== 'flow' || !relay(ev)) return;
    const key = domainFamily(ev.dstName || ev.dst) || ev.dstIp;
    if (key && dev.hosts.size < 64) dev.hosts.add(key);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || ev.type !== 'flow' || !relay(ev)) return;
    const key = domainFamily(ev.dstName || ev.dst) || ev.dstIp;
    if (!key || dev.hosts.has(key)) return;
    const hour = Math.floor(ev.ts / HOUR);
    const slot = `${key}|${hour}`;
    const total = (dev.bytes.get(slot) || 0) + (ev.bytesOut || 0);
    if (dev.bytes.size > 64) {
      const oldest = dev.bytes.keys().next().value;
      if (oldest !== undefined) dev.bytes.delete(oldest);
    }
    dev.bytes.set(slot, total);
    if (total < FIVE_MB) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: `${total} bytes out via ${key}`,
      expected: 'a relay host already in the baseline, or under 5 MB',
      data: { host: key, bytesOut: total },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { hosts: [...dev.hosts], fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.hosts = new Set();
    dev.bytes = new Map();
    dev.fired = Boolean(state && state.fired);
    if (!state || !Array.isArray(state.hosts)) return;
    if (state.hosts.length > 64)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array hosts exceeds cap');
    for (const host of state.hosts) dev.hosts.add(String(host));
  },

  memoryEstimate() {
    return 64;
  },
};

module.exports = detector;
