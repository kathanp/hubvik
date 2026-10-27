'use strict';

const { entropy, explainThreshold } = require('./lib');
const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const FAMILY_CAP = 64;
const NAME_CAP = 64;

const detector = {
  id: 'dns-tunnel',
  version: 1,
  meta: {
    consumes: ['dns'],
    rel: '0.3',
    fpRisk: 'Low with the combined score',
    explains: true,
    attack: ['T1071.004'],
    stage: 'impact',
  },
  requires: ['T2'],
  category: 'dns',
  hardRule: true,
  defaults: { minScore: 3, severity: 'critical' },

  createState() {
    return {
      win: null,
      byFamily: new Map(),
      queries: 0,
      oddType: false,
      long: false,
      rich: false,
      fired: false,
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !ev.qname) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.byFamily = new Map();
      dev.queries = 0;
      dev.oddType = false;
      dev.long = false;
      dev.rich = false;
      dev.fired = false;
    }
    dev.queries += 1;
    const label = ev.qname.split('.')[0];
    if (label.length > 40) dev.long = true;
    if (entropy(label) > 3.5 && label.length >= 12) dev.rich = true;
    noteName(dev, ev.qname);
    const qtype = String(ev.qtype || '').toUpperCase();
    if (qtype === 'TXT' || qtype === 'NULL' || qtype === 'CNAME') dev.oddType = true;
    if (dev.fired) return;
    let score = 0;
    if (dev.long) score += 1;
    if (dev.rich) score += 1;
    if (manyUnderOneParent(dev)) score += 1;
    if (dev.oddType) score += 1;
    if (dev.queries > 30) score += 1;
    if (score < ctx.options.minScore) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${ev.qname} (score ${score})`,
      expected: `tunnel score < ${ctx.options.minScore}`,
      data: { score, qname: ev.qname, queries: dev.queries },
      explain: explainThreshold({
        test: 'gte',
        observed: score,
        threshold: ctx.options.minScore,
        formula: `minScore=${ctx.options.minScore}`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { queries: dev.queries };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.byFamily = new Map();
    dev.queries = 0;
    dev.oddType = false;
    dev.long = false;
    dev.rich = false;
    dev.fired = false;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    let names = 0;
    for (const set of dev.byFamily.values()) names += set.size;
    return names * 48 + dev.byFamily.size * 24 + 24;
  },
};

/**
 * @param {any} dev
 * @param {string} qname
 */
function noteName(dev, qname) {
  const family = domainFamily(qname);
  if (!family) return;
  let names = dev.byFamily.get(family);
  if (!names) {
    if (dev.byFamily.size >= FAMILY_CAP) return;
    names = new Set();
    dev.byFamily.set(family, names);
  }
  if (names.size < NAME_CAP) names.add(qname);
}

/**
 * @param {any} dev
 * @returns {boolean}
 */
function manyUnderOneParent(dev) {
  for (const names of dev.byFamily.values()) {
    if (names.size > 10) return true;
  }
  return false;
}

module.exports = detector;
