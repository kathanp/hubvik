'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'discovery-spoof',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Low', consumes: ['discovery'] },
  requires: ['T4'],
  category: 'identity',
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return { names: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    claim(dev, ev, true);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const clash = claim(dev, ev, false);
    if (!clash || dev.fired.has(clash)) return;
    if (dev.fired.size >= 64) return;
    dev.fired.add(clash);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${ev.name} announced by ${ev.mac}`,
      expected: 'the first MAC that announced this name',
      data: { name: ev.name, mac: ev.mac },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { names: [...dev.names.entries()].slice(0, 5000) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.names = new Map(Array.isArray(state.names) ? state.names.slice(0, 5000) : []);
    dev.fired = new Set();
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.names.size * 48 + 16;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} learning
 * @returns {string | null}
 */
function claim(dev, ev, learning) {
  if (ev.type !== 'discovery' || typeof ev.name !== 'string' || typeof ev.mac !== 'string')
    return null;
  const prev = dev.names.get(ev.name);
  if (!prev) {
    if (dev.names.size >= 5000) return null;
    dev.names.set(ev.name, ev.mac);
    return null;
  }
  if (prev === ev.mac || learning) return null;
  return `${ev.name}|${ev.mac}`;
}

module.exports = detector;
