'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { createP2, push, quantile } = require('../engine/stats/p2');
const { assertState } = require('./state');

const TYPES = { flow: 0, dns: 1, tls: 2, app: 3 };

/**
 * @param {any} ev
 * @param {Set<string>} known
 * @returns {number | null}
 */
function token(ev, known) {
  const type = TYPES[/** @type {keyof typeof TYPES} */ (ev.type)];
  if (type == null) return null;
  const family = domainFamily(ev.dstName || ev.qname || ev.sni || ev.target || ev.dst) || '';
  const inBase = family && known.has(family) ? 1 : 0;
  const port = ev.dstPort || 0;
  const portClass = port < 1024 ? 0 : port < 49152 ? 1 : 2;
  const dir = ev.direction === 'in' ? 0 : ev.direction === 'lan' ? 1 : 2;
  return type * 18 + inBase * 9 + portClass * 3 + dir;
}

const detector = {
  id: 'sequence-surprise',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: ['flow', 'dns', 'tls', 'app'],
  },
  requires: ['T0'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'medium' },

  createState() {
    return {
      known: new Set(),
      counts: new Map(),
      other: 0,
      prev: null,
      p2: createP2(0.999),
      win: null,
      surprise: 0,
      steps: 0,
      streak: 0,
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    if (ctx.sequence) observe(dev, ev, true);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ctx.sequence) observe(dev, ev, false);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (!ctx.sequence) return;
    const steps = dev.steps;
    const mean = steps > 0 ? dev.surprise / steps : 0;
    dev.surprise = 0;
    dev.steps = 0;
    dev.win = null;
    if (steps < 20) {
      dev.streak = 0;
      return;
    }
    if (ctx.learning) {
      push(dev.p2, mean);
      dev.streak = 0;
      return;
    }
    if (dev.p2.count < 5 || mean <= quantile(dev.p2)) {
      dev.streak = 0;
      return;
    }
    dev.streak += 1;
    if (dev.streak < 3) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: win.start,
      actual: `mean surprise ${mean.toFixed(3)}`,
      expected: `at or below the learned 99.9 percentile ${quantile(dev.p2)}`,
      data: { surprise: mean, transitions: steps },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      known: [...dev.known],
      counts: [...dev.counts.entries()],
      other: dev.other,
      prev: dev.prev,
      streak: dev.streak,
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.known = new Set();
    dev.counts = new Map();
    dev.other = 0;
    dev.prev = null;
    dev.p2 = createP2(0.999);
    dev.win = null;
    dev.surprise = 0;
    dev.steps = 0;
    dev.streak = 0;
    if (!state) return;
    if (Array.isArray(state.known)) {
      if (state.known.length > 256)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array known exceeds cap');
      for (const name of state.known) dev.known.add(String(name));
    }
    if (Array.isArray(state.counts)) {
      if (state.counts.length > 128)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array counts exceeds cap');
      for (const pair of state.counts) {
        if (Array.isArray(pair)) dev.counts.set(String(pair[0]), Number(pair[1]) || 0);
      }
    }
    if (Number.isInteger(state.other)) dev.other = state.other;
    if (typeof state.prev === 'number') dev.prev = state.prev;
    if (Number.isInteger(state.streak)) dev.streak = state.streak;
  },

  memoryEstimate() {
    return 256;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} learning
 */
function observe(dev, ev, learning) {
  const family = domainFamily(ev.dstName || ev.qname || ev.sni || ev.target || ev.dst);
  if (learning && family && dev.known.size < 256) dev.known.add(family);
  const next = token(ev, dev.known);
  if (next == null) return;
  const start = ev.ts;
  if (dev.win == null) dev.win = start;
  if (dev.prev != null) {
    const key = `${dev.prev}|${next}`;
    const count = dev.counts.get(key) || 0;
    if (learning) {
      if (count > 0 || dev.counts.size < 128) dev.counts.set(key, count + 1);
      else dev.other += 1;
    }
    let total = dev.other;
    for (const [row, n] of dev.counts) {
      if (row.startsWith(`${dev.prev}|`)) total += n;
    }
    const hit = dev.counts.get(key) || 0;
    const p = (hit + 0.5) / (total + 0.5 * 72);
    dev.surprise += -Math.log2(p);
    dev.steps += 1;
  }
  dev.prev = next;
}

module.exports = detector;
