'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const WORDS = new Set(require('../data/words.json'));
const FAMILIES = 256;
const NAMES = 32;
const MIN_NAMES = 8;

const detector = {
  id: 'dictionary-dga',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low per burst. NXDOMAIN or a short TTL is required',
    consumes: ['dns'],
    attack: ['T1568.002'],
  },
  requires: ['T2'],
  category: 'dns',
  hardRule: false,
  defaults: { severity: 'medium' },

  createState() {
    return { learned: new Set(), win: null, names: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const family = familyOf(ev);
    if (!family || dev.learned.has(family) || dev.learned.size >= FAMILIES) return;
    dev.learned.add(family);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || !joined(ev)) return;
    const family = familyOf(ev);
    if (!family || dev.learned.has(family)) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.names = new Set();
      dev.fired = false;
    }
    if (dev.names.size < NAMES) dev.names.add(ev.qname);
    if (dev.names.size < MIN_NAMES) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${dev.names.size} dictionary names`,
      expected: 'fewer than 8 joined dictionary names in a new family',
      data: { family, names: dev.names.size },
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
    dev.win = null;
    dev.names = new Set();
    dev.fired = false;
    if (!state || !Array.isArray(state.learned)) return;
    if (state.learned.length > FAMILIES)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array learned exceeds cap');
    for (const family of state.learned) dev.learned.add(String(family));
  },

  memoryEstimate() {
    return 512;
  },
};

/**
 * @param {any} ev
 * @returns {string | null}
 */
function familyOf(ev) {
  if (!ev || ev.type !== 'dns') return null;
  return domainFamily(ev.qname);
}

/**
 * @param {any} ev
 * @returns {boolean}
 */
function joined(ev) {
  if (!ev || ev.type !== 'dns') return false;
  if (!(ev.rcode === 'NXDOMAIN' || lowTtl(ev))) return false;
  const label = String(ev.qname || '')
    .split('.')[0]
    .toLowerCase();
  if (!/^[a-z]{8,30}$/.test(label)) return false;
  return segmented(label);
}

/**
 * @param {any} ev
 * @returns {boolean}
 */
function lowTtl(ev) {
  if (!Array.isArray(ev.answers) || ev.answers.length === 0) return false;
  return ev.answers.some((answer) => typeof answer.ttl === 'number' && answer.ttl <= 300);
}

/**
 * True when the label is 2 to 4 whole dictionary words.
 * @param {string} label
 * @returns {boolean}
 */
function segmented(label) {
  const reach = new Array(label.length + 1).fill(-1);
  reach[0] = 0;
  for (let i = 0; i < label.length; i += 1) {
    if (reach[i] < 0 || reach[i] >= 4) continue;
    for (let end = i + 3; end <= label.length && end <= i + 12; end += 1) {
      if (!WORDS.has(label.slice(i, end))) continue;
      const words = reach[i] + 1;
      if (reach[end] < 0 || words < reach[end]) reach[end] = words;
    }
  }
  const used = reach[label.length];
  return used >= 2 && used <= 4;
}

module.exports = detector;
