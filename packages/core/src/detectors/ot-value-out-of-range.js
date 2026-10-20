'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'ot-value-out-of-range',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { minSamples: 3, severity: 'critical' },

  createState() {
    return { ranges: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const sample = numeric(ev);
    if (!sample) return;
    const row = dev.ranges.get(sample.target) || { min: sample.value, max: sample.value, n: 0 };
    row.min = Math.min(row.min, sample.value);
    row.max = Math.max(row.max, sample.value);
    row.n += 1;
    dev.ranges.set(sample.target, row);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const sample = numeric(ev);
    if (!sample || dev.fired.has(sample.target)) return;
    const row = dev.ranges.get(sample.target);
    if (!row || row.n < ctx.options.minSamples) return;
    if (sample.value >= row.min && sample.value <= row.max) return;
    dev.fired.add(sample.target);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${sample.target} = ${sample.value}`,
      expected: `${row.min}..${row.max}`,
      data: { target: sample.target, value: sample.value, min: row.min, max: row.max },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { ranges: [...dev.ranges.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    if (!Array.isArray(state.ranges))
      throw new Error('ot-value-out-of-range ranges must be an array');
    if (state.ranges.length > 5000)
      throw new Error('array ot-value-out-of-range.ranges exceeds cap');
    dev.ranges = new Map();
    dev.fired = new Set();
    for (const pair of state.ranges) {
      if (Array.isArray(pair) && pair[1] && typeof pair[1].n === 'number') {
        dev.ranges.set(String(pair[0]), pair[1]);
      }
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.ranges.size * 32 + 16;
  },
};

/**
 * @param {any} ev
 */
function numeric(ev) {
  if (ev.type !== 'app' || typeof ev.value !== 'number' || !ev.target) return null;
  return { target: `${ev.op}|${ev.target}`, value: ev.value };
}

module.exports = detector;
