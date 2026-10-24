'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');

const SEGMENTS = new Set(['cmd', 'command', 'set', 'ota', 'config', 'firmware']);
const CAP = 64;

/**
 * @param {string | undefined} topic
 * @returns {string | null}
 */
function prefixOf(topic) {
  if (!topic) return null;
  const parts = topic.split('/');
  if (!parts.some((part) => SEGMENTS.has(part))) return null;
  return parts.slice(0, 3).join('/');
}

const detector = {
  id: 'mqtt-will-takeover',
  version: 1,
  meta: {
    rel: '1.2',
    mode: 'shadow',
    fpRisk: 'Low. Legitimate will topics are learned',
    consumes: ['app'],
    attack: ['T0855'],
  },
  requires: ['T5'],
  category: 'app',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { learned: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type !== 'app' || ev.proto !== 'mqtt') return;
    const prefix = prefixOf(ev.target);
    if (!prefix || dev.learned.size >= CAP) return;
    dev.learned.add(`${ev.peerIp}|${prefix}`);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || ev.proto !== 'mqtt' || ev.op !== 'CONNECT') return;
    if (!Array.isArray(ev.flags) || !ev.flags.includes('will')) return;
    const prefix = prefixOf(ev.target);
    if (!prefix) return;
    const key = `${ev.peerIp}|${prefix}`;
    if (dev.learned.has(key)) return;
    if (dev.learned.size >= CAP) return;
    dev.learned.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.84,
      ts: ev.ts,
      actual: `${ev.peerIp} will ${ev.target}`,
      expected: 'a client already learned on this topic prefix',
      data: { peerIp: ev.peerIp, topic: ev.target },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { learned: [...dev.learned] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.learned = new Set();
    if (!state || !Array.isArray(state.learned)) return;
    if (state.learned.length > CAP)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array learned exceeds cap');
    for (const key of state.learned) dev.learned.add(String(key));
  },

  memoryEstimate() {
    return 128;
  },
};

module.exports = detector;
