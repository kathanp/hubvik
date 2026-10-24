'use strict';

const { HubvikError } = require('../errors');

const SUFFIXES = require('../data/doh.json');
const { assertState } = require('./state');

const CAP = 32;
const DAY = 86400000;

/**
 * @param {unknown} name
 * @returns {string | null}
 */
function suffixOf(name) {
  if (typeof name !== 'string' || name.length === 0) return null;
  const host = name.toLowerCase().replace(/\.$/, '');
  for (const suffix of SUFFIXES) {
    if (host === suffix || host.endsWith(`.${suffix}`)) return suffix;
  }
  return null;
}

/**
 * @param {any} ev
 * @returns {string | null}
 */
function nameOf(ev) {
  if (!ev || ev.dstPort !== 443) return null;
  if (ev.type === 'tls') return suffixOf(ev.sni);
  if (ev.type === 'flow') return suffixOf(ev.dstName);
  return null;
}

const detector = {
  id: 'doh-bypass',
  version: 1,
  meta: {
    rel: '1.2',
    mode: 'shadow',
    fpRisk: "Low once the device's own DoH resolver is in the baseline",
    consumes: ['tls', 'flow'],
    attack: ['T1071.004'],
  },
  requires: ['T3'],
  category: 'dns',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { learned: new Set(), alerted: new Map() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const suffix = nameOf(ev);
    if (!suffix || dev.learned.size >= CAP) return;
    dev.learned.add(suffix);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const suffix = nameOf(ev);
    if (!suffix || dev.learned.has(suffix)) return;
    const prev = dev.alerted.get(suffix);
    if (prev != null && ev.ts - prev < DAY) return;
    if (!dev.alerted.has(suffix) && dev.alerted.size >= CAP) return;
    dev.alerted.set(suffix, ev.ts);
    return {
      severity: ctx.options.severity,
      confidence: 0.86,
      ts: ev.ts,
      actual: suffix,
      expected: 'a learned DNS-over-HTTPS resolver',
      data: { suffix, port: 443 },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { learned: [...dev.learned], alerted: [...dev.alerted] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.learned = new Set();
    dev.alerted = new Map();
    if (!state) return;
    if (Array.isArray(state.learned)) {
      if (state.learned.length > CAP)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array learned exceeds cap');
      for (const suffix of state.learned) dev.learned.add(String(suffix));
    }
    if (Array.isArray(state.alerted)) {
      if (state.alerted.length > CAP)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array alerted exceeds cap');
      for (const row of state.alerted) {
        if (Array.isArray(row)) dev.alerted.set(String(row[0]), Number(row[1]));
      }
    }
  },

  memoryEstimate() {
    return 256;
  },
};

module.exports = detector;
