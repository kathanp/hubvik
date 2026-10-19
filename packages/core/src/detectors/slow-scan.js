'use strict';

const { LruSet } = require('../engine/caps');
const { createHll, merge, count } = require('../engine/stats/hll');
const { push } = require('../engine/stats/welford');
const { assertState, readStrings } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const detector = {
  id: 'slow-scan',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['flow'],
    explains: true,
  },
  requires: ['T1'],
  category: 'scan',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minPairs: 40 },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return {
      pairs: new LruSet(caps.maxDestinations),
      day: null,
      today: 0,
      closed: false,
      daily: emptyStats(),
      fired: false,
    };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const pair = pairOf(ev);
    if (!pair) return;
    const day = Math.floor(ev.ts / 86400000);
    if (dev.day !== day) {
      if (dev.day != null) pushDay(dev.daily, dev.today);
      dev.day = day;
      dev.today = 0;
    }
    if (dev.pairs.has(pair)) return;
    dev.pairs.add(pair);
    dev.today += 1;
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (!dev.closed) {
      dev.closed = true;
      if (dev.day != null) pushDay(dev.daily, dev.today);
    }
    const pair = pairOf(ev);
    if (!pair || dev.fired) return;
    if (!dev.pairs.has(pair)) ctx.horizon(dev).addPair(pair);
    let sketch = createHll({ p: 8 });
    for (const row of ctx.horizon(dev).last(24)) sketch = merge(sketch, row.newPairsHll);
    const estimate = count(sketch);
    const learnedMax = dev.daily.count > 0 ? dev.daily.max : 0;
    const threshold = Math.max(ctx.options.minPairs, 3 * learnedMax);
    if (!(estimate > threshold)) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      ts: ev.ts,
      explain: explainThreshold({
        test: 'gt',
        observed: estimate,
        threshold,
        formula: 'max(minPairs, 3 × learned daily max)',
        learned: { dailyMax: learnedMax },
      }),
      data: { estimate, threshold, learnedMax },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    return {
      pairs: dev.pairs.toArray(),
      day: dev.day,
      today: dev.today,
      closed: dev.closed,
      daily: { ...dev.daily },
      fired: dev.fired,
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    const pairs = readStrings(state.pairs, caps.maxDestinations, caps.maxString, 'pairs');
    dev.pairs = new LruSet(caps.maxDestinations);
    for (const pair of pairs) dev.pairs.add(pair);
    dev.day = typeof state.day === 'number' ? state.day : null;
    dev.today = typeof state.today === 'number' ? state.today : 0;
    dev.closed = Boolean(state.closed);
    dev.fired = Boolean(state.fired);
    dev.daily = emptyStats();
    if (state.daily && typeof state.daily === 'object') {
      dev.daily.count = state.daily.count || 0;
      dev.daily.mean = state.daily.mean || 0;
      dev.daily.m2 = state.daily.m2 || 0;
      dev.daily.min = state.daily.min || 0;
      dev.daily.max = state.daily.max || 0;
    }
  },
};

/** @returns {{ count: number, mean: number, m2: number, min: number, max: number }} */
function emptyStats() {
  return { count: 0, mean: 0, m2: 0, min: 0, max: 0 };
}

/**
 * @param {any} stats
 * @param {number} value
 */
function pushDay(stats, value) {
  if (stats.count === 0) {
    stats.count = 1;
    stats.mean = value;
    stats.m2 = 0;
    stats.min = value;
    stats.max = value;
    return;
  }
  push(stats, value);
}

/**
 * @param {any} ev
 * @returns {string | null}
 */
function pairOf(ev) {
  if (!ev || ev.type !== 'flow' || typeof ev.dstIp !== 'string' || isGroupDst(ev.dstIp))
    return null;
  if (typeof ev.dstPort !== 'number') return null;
  return `${ev.dstIp}:${ev.dstPort}`;
}

module.exports = detector;
