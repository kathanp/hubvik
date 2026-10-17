'use strict';

const { median } = require('./lib');
const { assertState, readStrings, fillSet } = require('./state');
const { LruSet } = require('../engine/caps');

const detector = {
  id: 'new-beacon',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk:
      '**High if applied to everything**: IoT devices beacon to vendors all day. Only score destinations outside the baseline',
    attack: ['T1071'],
    stage: 'c2',
  },
  requires: ['T1'],
  category: 'timing',
  defaults: { minCount: 20, maxMadRatio: 0.25, severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { baseline: new LruSet(caps.maxDestinations), tracks: new Map() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const dst = peer(ev);
    if (dst) dev.baseline.add(dst);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const dst = peer(ev);
    if (!dst || dev.baseline.has(dst)) return;
    let row = dev.tracks.get(dst);
    if (!row) {
      if (dev.tracks.size >= 16) return;
      row = { gaps: [], sizes: [], last: null, count: 0, fired: false };
      dev.tracks.set(dst, row);
    }
    if (row.fired) return;
    if (row.last != null && row.gaps.length < 32) row.gaps.push(ev.ts - row.last);
    row.last = ev.ts;
    const size = ev.bytesOut ?? ev.bytes ?? 0;
    if (row.sizes.length < 32) row.sizes.push(size);
    row.count += 1;
    if (row.count < ctx.options.minCount || row.gaps.length < ctx.options.minCount - 1) return;
    const med = median(row.gaps);
    if (med <= 0) return;
    const mad = median(row.gaps.map((/** @type {number} */ gap) => Math.abs(gap - med)));
    if (mad / med > ctx.options.maxMadRatio) return;
    const hi = Math.max(...row.sizes);
    const lo = Math.min(...row.sizes);
    if (lo > 0 && hi / lo > 3) return;
    row.fired = true;
    const score = Math.max(0, Math.min(1, 1 - mad / med));
    return {
      severity: ctx.options.severity,
      confidence: score,
      ts: ev.ts,
      actual: dst,
      expected: 'no periodic contact off the baseline',
      data: { score, count: row.count, medianGap: med },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { baseline: dev.baseline.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.baseline = fillSet(
      readStrings(state.baseline, caps.maxDestinations, caps.maxString, 'baseline'),
      caps.maxDestinations,
    );
    dev.tracks = new Map();
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.baseline.size * 32 + dev.tracks.size * 256;
  },
};

/**
 * @param {any} ev
 * @returns {string | null}
 */
function peer(ev) {
  if (ev.type !== 'flow') return null;
  return ev.dstName || ev.dstIp || null;
}

module.exports = detector;
