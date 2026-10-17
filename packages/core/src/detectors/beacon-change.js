'use strict';

const { median } = require('./lib');
const { assertState } = require('./state');

const detector = {
  id: 'beacon-change',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.4',
    fpRisk: 'Medium (firmware updates)',
  },
  requires: ['T1'],
  category: 'timing',
  defaults: { minGaps: 8, factor: 2, severity: 'medium' },

  createState() {
    return { learned: new Map(), tracks: new Map() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    note(dev, ev, false);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    return note(dev, ev, true, ctx);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { learned: [...dev.learned.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.learned = new Map();
    dev.tracks = new Map();
    if (!Array.isArray(state.learned) || state.learned.length > 5000) return;
    for (const pair of state.learned) {
      if (Array.isArray(pair) && pair.length === 2) dev.learned.set(String(pair[0]), pair[1]);
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.learned.size * 32 + dev.tracks.size * 64;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} alert
 * @param {any} [ctx]
 */
function note(dev, ev, alert, ctx) {
  if (ev.type !== 'flow') return;
  const dst = ev.dstName || ev.dstIp;
  if (!dst) return;
  let row = dev.tracks.get(dst);
  if (!row) {
    if (dev.tracks.size >= 32) return;
    row = { gaps: [], last: null, fired: false };
    dev.tracks.set(dst, row);
  }
  if (row.last != null && row.gaps.length < 32) row.gaps.push(ev.ts - row.last);
  row.last = ev.ts;
  if (!alert) {
    if (row.gaps.length >= 4) dev.learned.set(dst, median(row.gaps));
    return;
  }
  const base = dev.learned.get(dst);
  if (!base || row.fired || row.gaps.length < ctx.options.minGaps) return;
  const now = median(row.gaps.slice(-ctx.options.minGaps));
  if (now <= base * ctx.options.factor && base <= now * ctx.options.factor) return;
  row.fired = true;
  return {
    severity: ctx.options.severity,
    confidence: 0.7,
    ts: ev.ts,
    actual: `${dst} every ${Math.round(now / 1000)}s`,
    expected: `about every ${Math.round(base / 1000)}s`,
    data: { dst, medianMs: now, learnedMs: base },
  };
}

module.exports = detector;
