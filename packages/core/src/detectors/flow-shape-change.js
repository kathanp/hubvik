'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const CAP = 16;

/**
 * @param {number} len
 * @returns {number}
 */
function bucket(len) {
  const sign = len < 0 ? 0 : 8;
  const mag = Math.min(7, Math.floor(Math.log2(Math.abs(len) + 1)));
  return sign + mag;
}

/**
 * @param {number[]} left
 * @param {number[]} right
 * @returns {number}
 */
function jensenShannon(left, right) {
  let sumLeft = 0;
  let sumRight = 0;
  for (let i = 0; i < 16; i += 1) {
    sumLeft += left[i];
    sumRight += right[i];
  }
  if (sumLeft === 0 || sumRight === 0) return 0;
  let div = 0;
  for (let i = 0; i < 16; i += 1) {
    const p = left[i] / sumLeft;
    const q = right[i] / sumRight;
    const m = (p + q) / 2;
    if (p > 0 && m > 0) div += p * Math.log2(p / m);
    if (q > 0 && m > 0) div += q * Math.log2(q / m);
  }
  return div / 2;
}

const detector = {
  id: 'flow-shape-change',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Medium after firmware updates. Inactive until a host supplies splt',
    consumes: ['flow'],
  },
  requires: ['T1'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'high' },

  /** @param {any} _ev @param {any} ctx */
  prepare(_ev, ctx) {
    return ctx.flowShape === true;
  },

  createState() {
    return { families: new Map(), recent: [], fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    if (!ctx.flowShape) return;
    const row = shape(ev);
    if (!row) return;
    const hist = take(dev, row.family);
    for (const item of row.buckets) hist[item] += 1;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!ctx.flowShape || dev.fired) return;
    const row = shape(ev);
    if (!row) return;
    const hist = dev.families.get(row.family);
    if (!hist) return;
    dev.recent.push(row.buckets);
    if (dev.recent.length > 20) dev.recent.shift();
    if (dev.recent.length < 20) return;
    const now = new Array(16).fill(0);
    for (const buckets of dev.recent) {
      for (const item of buckets) now[item] += 1;
    }
    const divergence = jensenShannon(hist, now);
    if (divergence <= 0.4) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `Jensen-Shannon ${divergence.toFixed(3)} on ${row.family}`,
      expected: 'divergence at most 0.4',
      data: { family: row.family, divergence },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      families: [...dev.families.entries()],
      fired: dev.fired,
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.families = new Map();
    dev.recent = [];
    dev.fired = Boolean(state && state.fired);
    if (!state || !Array.isArray(state.families)) return;
    if (state.families.length > CAP)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array families exceeds cap');
    for (const pair of state.families) {
      if (!Array.isArray(pair) || !Array.isArray(pair[1]) || pair[1].length !== 16) continue;
      dev.families.set(String(pair[0]), pair[1].map(Number));
    }
  },

  memoryEstimate() {
    return 512;
  },
};

/**
 * @param {any} ev
 * @returns {{ family: string, buckets: number[] } | null}
 */
function shape(ev) {
  if (!ev || ev.type !== 'flow' || !ev.splt || !Array.isArray(ev.splt.len)) return null;
  const family = domainFamily(ev.dstName || ev.dst);
  if (!family) return null;
  return {
    family,
    buckets: ev.splt.len.slice(0, 4).map((/** @type {number} */ len) => bucket(len)),
  };
}

/**
 * @param {any} dev
 * @param {string} family
 * @returns {number[]}
 */
function take(dev, family) {
  let hist = dev.families.get(family);
  if (!hist) {
    if (dev.families.size >= CAP) {
      const oldest = dev.families.keys().next().value;
      if (oldest !== undefined) dev.families.delete(oldest);
    }
    hist = new Array(16).fill(0);
    dev.families.set(family, hist);
  } else {
    dev.families.delete(family);
    dev.families.set(family, hist);
  }
  return hist;
}

module.exports = detector;
