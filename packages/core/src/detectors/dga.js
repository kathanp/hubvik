'use strict';

const { entropy } = require('./lib');
const { assertState } = require('./state');
const BIGRAMS = new Set(require('../data/bigrams.json'));

const detector = {
  id: 'dga',
  version: 1,
  meta: {
    consumes: ['dns'],
    rel: '0.3',
    fpRisk: 'Medium per name, low per burst',
    attack: ['T1568.002'],
    stage: 'c2',
  },
  requires: ['T2'],
  category: 'dns',
  defaults: { minBurst: 5, severity: 'high' },

  createState() {
    return { win: null, count: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !suspicious(ev.qname)) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.count = 0;
      dev.fired = false;
    }
    dev.count += 1;
    if (dev.fired || dev.count < ctx.options.minBurst) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${dev.count} generated-looking names`,
      expected: `< ${ctx.options.minBurst} per window`,
      data: { count: dev.count, sample: ev.qname },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { count: dev.count };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.count = 0;
    dev.fired = false;
  },

  memoryEstimate() {
    return 16;
  },
};

/**
 * @param {string} name
 */
function suspicious(name) {
  if (!name) return false;
  const label = name.split('.')[0];
  if (label.length < 12) return false;
  const letters = label.toLowerCase().replace(/[^a-z]/g, '');
  if (letters.length < 8) return false;
  let hits = 0;
  for (let i = 0; i < letters.length - 1; i++) {
    if (BIGRAMS.has(letters.slice(i, i + 2))) hits += 1;
  }
  const pairs = Math.max(1, letters.length - 1);
  const vowels = (letters.match(/[aeiou]/g) || []).length / letters.length;
  const digits = (label.match(/\d/g) || []).length / label.length;
  return entropy(letters) >= 3.3 && hits / pairs < 0.2 && (vowels < 0.25 || digits > 0.15);
}

module.exports = detector;
