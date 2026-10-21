'use strict';

const { HubvikError } = require('../errors');

const { LruSet } = require('../engine/caps');
const { assertState, readStrings } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const CAP = 64;
const LOG = Math.log(1.5);

const detector = {
  id: 'jitter-beacon',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: ['flow'],
    explains: true,
  },
  requires: ['T1'],
  category: 'timing',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minCount: 30, minSpanMs: 2 * 3600e3 },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return { baseline: new LruSet(caps.maxDestinations), tracks: new Map() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const dst = dstOf(ev);
    if (dst) dev.baseline.add(dst);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const dst = dstOf(ev);
    if (!dst || dev.baseline.has(dst)) return;
    let row = dev.tracks.get(dst);
    if (row) dev.tracks.delete(dst);
    else if (dev.tracks.size >= CAP) dev.tracks.delete(dev.tracks.keys().next().value);
    if (!row) {
      row = {
        buckets: new Array(16).fill(0),
        count: 0,
        gaps: 0,
        first: ev.ts,
        last: null,
        min: ev.bytesOut || 0,
        max: ev.bytesOut || 0,
        fired: false,
      };
    }
    dev.tracks.set(dst, row);
    if (row.fired) return;
    const size = ev.bytesOut || 0;
    if (size > 0 && (row.min === 0 || size < row.min)) row.min = size;
    if (size > row.max) row.max = size;
    if (row.last != null && ev.ts > row.last) {
      row.buckets[bucket(ev.ts - row.last)] += 1;
      row.gaps += 1;
    }
    row.last = ev.ts;
    row.count += 1;
    if (row.count < ctx.options.minCount) return;
    if (ev.ts - row.first < ctx.options.minSpanMs) return;
    if (!(row.min > 0) || row.max / row.min > 4) return;
    const share = modalShare(row.buckets, row.gaps);
    if (!(share >= 0.6)) return;
    row.fired = true;
    return {
      severity: ctx.options.severity,
      ts: ev.ts,
      explain: explainThreshold({
        test: 'gte',
        observed: share,
        threshold: 0.6,
        formula: 'modal 3 adjacent buckets / gaps',
        learned: { count: row.count, sizeRatio: row.max / row.min },
      }),
      data: { dst, count: row.count, share, sizeRatio: row.max / row.min },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    return {
      baseline: dev.baseline.toArray(),
      tracks: [...dev.tracks.entries()],
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.baseline = new LruSet(caps.maxDestinations);
    for (const dst of readStrings(
      state.baseline,
      caps.maxDestinations,
      caps.maxString,
      'baseline',
    )) {
      dev.baseline.add(dst);
    }
    dev.tracks = new Map();
    if (!Array.isArray(state.tracks)) return;
    if (state.tracks.length > CAP)
      throw new HubvikError('ARRAY_TRACKS_EXCEEDS_CAP', 'array tracks exceeds cap');
    for (const pair of state.tracks) {
      if (!Array.isArray(pair) || pair.length !== 2) continue;
      const row = pair[1];
      if (
        !row ||
        typeof row !== 'object' ||
        !Array.isArray(row.buckets) ||
        row.buckets.length !== 16
      ) {
        continue;
      }
      dev.tracks.set(String(pair[0]), {
        buckets: row.buckets.slice(),
        count: row.count || 0,
        gaps: row.gaps || 0,
        first: row.first || 0,
        last: row.last,
        min: row.min || 0,
        max: row.max || 0,
        fired: Boolean(row.fired),
      });
    }
  },
};

/**
 * @param {number} gapMs
 */
function bucket(gapMs) {
  const seconds = gapMs / 1000;
  if (!(seconds > 0)) return 0;
  const index = Math.floor(Math.log(seconds) / LOG);
  if (index < 0) return 0;
  if (index > 15) return 15;
  return index;
}

/**
 * @param {number[]} buckets
 * @param {number} gaps
 */
function modalShare(buckets, gaps) {
  if (gaps <= 0) return 0;
  let mode = 0;
  for (let i = 1; i < buckets.length; i += 1) if (buckets[i] > buckets[mode]) mode = i;
  let best = 0;
  const from = Math.max(0, mode - 2);
  const to = Math.min(mode, buckets.length - 3);
  for (let start = from; start <= to; start += 1) {
    const sum = buckets[start] + buckets[start + 1] + buckets[start + 2];
    if (sum > best) best = sum;
  }
  return best / gaps;
}

/**
 * @param {any} ev
 * @returns {string | null}
 */
function dstOf(ev) {
  if (!ev || ev.type !== 'flow' || typeof ev.dstIp !== 'string' || isGroupDst(ev.dstIp))
    return null;
  return ev.dstIp;
}

module.exports = detector;
