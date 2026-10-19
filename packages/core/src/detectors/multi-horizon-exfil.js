'use strict';

const { push } = require('../engine/stats/welford');
const { createP2, push: pushP2, quantile, toJSON, fromJSON } = require('../engine/stats/p2');
const { createCusum, push: pushCusum } = require('../engine/stats/cusum');
const { assertState } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const HOUR = 3600e3;
const DAY = 24 * HOUR;

const detector = {
  id: 'multi-horizon-exfil',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: ['flow'],
    explains: true,
  },
  requires: ['T1'],
  category: 'volume',
  hardRule: false,
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return {
      hourly: emptyStats(),
      daily: null,
      hour: null,
      hourBytes: 0,
      day: null,
      dayBytes: 0,
      flushed: false,
      fired: false,
    };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    if (!countable(ev)) return;
    const hour = Math.floor(ev.ts / HOUR);
    const day = Math.floor(ev.ts / DAY);
    if (dev.hour == null) dev.hour = hour;
    if (hour !== dev.hour) {
      pushHour(dev.hourly, dev.hourBytes);
      dev.hour = hour;
      dev.hourBytes = 0;
    }
    if (dev.day == null) dev.day = day;
    if (day !== dev.day) {
      rememberDay(dev);
      dev.day = day;
      dev.dayBytes = 0;
    }
    dev.hourBytes += ev.bytesOut || 0;
    dev.dayBytes += ev.bytesOut || 0;
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (!countable(ev) || dev.fired) return;
    if (!dev.flushed) {
      dev.flushed = true;
      if (dev.hour != null) pushHour(dev.hourly, dev.hourBytes);
      if (dev.day != null) rememberDay(dev);
    }
    if (dev.hourly.count < 2) return;
    const sigma = Math.sqrt(dev.hourly.m2 / (dev.hourly.count - 1));
    const limit = sigma > 0 ? 8 * sigma : 1;
    const daily = dev.daily ? fromJSON(dev.daily) : null;
    if (!daily || daily.count < 1) return;
    const bar = 1.5 * quantile(daily);
    const rows = ctx.horizon(dev).last(24);
    let total = 0;
    for (const row of rows) total += row.bytesOut;
    const cusum = createCusum({ k: 0.5 * sigma, h: limit, mean: dev.hourly.mean });
    for (const row of rows) pushCusum(cusum, row.bytesOut);
    if (!cusum.alarmed || !(total > bar)) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      ts: ev.ts,
      explain: explainThreshold({
        test: 'gt',
        observed: total,
        threshold: bar,
        formula: '24 h bytesOut > 1.5 × learned daily p99, and Page CUSUM h = 8σ',
        learned: { mean: dev.hourly.mean, sigma, h: limit },
      }),
      data: { total, bar, sigma, h: limit, cusum: cusum.high },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    return {
      hourly: { ...dev.hourly },
      daily: dev.daily,
      hour: dev.hour,
      hourBytes: dev.hourBytes,
      day: dev.day,
      dayBytes: dev.dayBytes,
      flushed: dev.flushed,
      fired: dev.fired,
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.hourly = emptyStats();
    if (state.hourly && typeof state.hourly === 'object') {
      dev.hourly.count = state.hourly.count || 0;
      dev.hourly.mean = state.hourly.mean || 0;
      dev.hourly.m2 = state.hourly.m2 || 0;
      dev.hourly.min = Number.isFinite(state.hourly.min) ? state.hourly.min : 0;
      dev.hourly.max = Number.isFinite(state.hourly.max) ? state.hourly.max : 0;
    }
    dev.daily = null;
    if (state.daily && typeof state.daily === 'object') {
      fromJSON(state.daily);
      dev.daily = state.daily;
    }
    dev.hour = typeof state.hour === 'number' ? state.hour : null;
    dev.hourBytes = state.hourBytes || 0;
    dev.day = typeof state.day === 'number' ? state.day : null;
    dev.dayBytes = state.dayBytes || 0;
    dev.flushed = Boolean(state.flushed);
    dev.fired = Boolean(state.fired);
  },
};

/**
 * @param {any} stats
 * @param {number} value
 */
function emptyStats() {
  return { count: 0, mean: 0, m2: 0, min: 0, max: 0 };
}

function pushHour(stats, value) {
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
 * @param {any} dev
 */
function rememberDay(dev) {
  const stats = dev.daily ? fromJSON(dev.daily) : createP2(0.99);
  pushP2(stats, dev.dayBytes);
  dev.daily = toJSON(stats);
}

/**
 * @param {any} ev
 */
function countable(ev) {
  return ev && ev.type === 'flow' && typeof ev.dstIp === 'string' && !isGroupDst(ev.dstIp);
}

module.exports = detector;
