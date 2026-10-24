'use strict';

const { HubvikError } = require('../errors');

const { LruSet } = require('../engine/caps');
const { median, isGroupDst } = require('./lib');
const { assertState, readStrings, fillSet } = require('./state');

const TRACKS = 32;
const GAPS = 64;
const MIN_GAPS = 24;
const MIN_PERIOD = 30_000;
const MAX_PERIOD = 6 * 3600_000;
const AUTOCORR = 0.35;

const detector = {
  id: 'spectral-beacon',
  version: 1,
  meta: {
    rel: '1.2',
    mode: 'shadow',
    fpRisk: 'Medium: NTP and push keepalives. Baseline destinations are excluded',
    consumes: ['flow'],
    attack: ['T1071'],
  },
  requires: ['T1'],
  category: 'timing',
  hardRule: false,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { baseline: new LruSet(caps.maxDestinations), tracks: new Map() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const dst = dstOf(ev);
    if (dst) dev.baseline.add(dst);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const dst = dstOf(ev);
    if (!dst || dev.baseline.has(dst)) return;
    const row = track(dev, dst);
    if (!row || row.fired) return;
    pushGap(row, ev);
    if (row.gaps.length < MIN_GAPS) return;
    if (newBeaconWouldFire(row) || jitterBeaconWouldFire(row, ev.ts)) return;
    const share = periodShare(row.gaps);
    if (share < AUTOCORR) return;
    row.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: dst,
      expected: 'no low-amplitude period off the baseline',
      data: { dst, gaps: row.gaps.length, autocorr: share },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { baseline: dev.baseline.toArray(), tracks: [...dev.tracks.entries()] };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.baseline = fillSet(
      readStrings(state.baseline, caps.maxDestinations, caps.maxString, 'baseline'),
      caps.maxDestinations,
    );
    dev.tracks = new Map();
    if (!Array.isArray(state.tracks)) return;
    if (state.tracks.length > TRACKS)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array tracks exceeds cap');
    for (const entry of state.tracks) {
      if (!Array.isArray(entry)) continue;
      dev.tracks.set(String(entry[0]), entry[1]);
    }
  },

  memoryEstimate() {
    return 512;
  },
};

/**
 * @param {any} ev
 * @returns {string | null}
 */
function dstOf(ev) {
  if (!ev || ev.type !== 'flow' || typeof ev.dstIp !== 'string' || isGroupDst(ev.dstIp))
    return null;
  return ev.dstIp;
}

/**
 * @param {any} dev
 * @param {string} dst
 */
function track(dev, dst) {
  let row = dev.tracks.get(dst);
  if (row) {
    dev.tracks.delete(dst);
    dev.tracks.set(dst, row);
    return row;
  }
  if (dev.tracks.size >= TRACKS) {
    const oldest = dev.tracks.keys().next().value;
    if (oldest != null) dev.tracks.delete(oldest);
  }
  row = { gaps: [], sizes: [], last: null, count: 0, first: null, fired: false };
  dev.tracks.set(dst, row);
  return row;
}

/**
 * @param {any} row
 * @param {any} ev
 */
function pushGap(row, ev) {
  if (row.first == null) row.first = ev.ts;
  if (row.last != null && row.gaps.length < GAPS) row.gaps.push(ev.ts - row.last);
  row.last = ev.ts;
  const size = ev.bytesOut || 0;
  if (row.sizes.length < GAPS) row.sizes.push(size);
  row.count += 1;
}

/**
 * Share of gaps that sit within half of the median period.
 * @param {number[]} gaps
 * @returns {number}
 */
function periodShare(gaps) {
  const med = median(gaps);
  if (!(med >= MIN_PERIOD && med <= MAX_PERIOD)) return 0;
  let hit = 0;
  for (const gap of gaps) {
    if (Math.abs(gap - med) <= med * 0.5) hit += 1;
  }
  return hit / gaps.length;
}

/**
 * new-beacon fires on a tight period with a stable size. Leave that case to it.
 * @param {any} row
 * @returns {boolean}
 */
function newBeaconWouldFire(row) {
  if (row.count < 20 || row.gaps.length < 19) return false;
  const med = median(row.gaps);
  if (!(med > 0)) return false;
  const mad = median(row.gaps.map((/** @type {number} */ gap) => Math.abs(gap - med)));
  if (mad / med > 0.25) return false;
  const hi = Math.max(...row.sizes);
  const lo = Math.min(...row.sizes.filter((/** @type {number} */ size) => size > 0));
  return !(lo > 0 && hi / lo > 3);
}

/**
 * jitter-beacon fires on a 2 h modal histogram. Leave that case to it.
 * @param {any} row
 * @param {number} ts
 * @returns {boolean}
 */
function jitterBeaconWouldFire(row, ts) {
  if (row.count < 30 || row.first == null || ts - row.first < 2 * 3600_000) return false;
  const hi = Math.max(...row.sizes);
  const lo = Math.min(...row.sizes.filter((/** @type {number} */ size) => size > 0));
  return !(lo > 0 && hi / lo > 4);
}

module.exports = detector;
