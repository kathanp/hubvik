'use strict';

const { push } = require('../engine/stats/welford');
const { createP2, push: pushP2, quantile, toJSON, fromJSON } = require('../engine/stats/p2');
const { createCusum, push: pushCusum } = require('../engine/stats/cusum');
const { assertState } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const HOUR = 3600e3;
const DAY = 24 * HOUR;
const COUNT = 0;
const MEAN = 1;
const M2 = 2;
const MIN = 3;
const MAX = 4;
const HOUR_SLOT = 5;
const HOUR_BYTES = 6;
const DAY_SLOT = 7;
const DAY_BYTES = 8;
const FLUSHED = 9;
const FIRED = 10;

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
    return blank();
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    if (!countable(ev)) return;
    const raw = dev.raw;
    const hour = Math.floor(ev.ts / HOUR);
    const day = Math.floor(ev.ts / DAY);
    if (Number.isNaN(raw[HOUR_SLOT])) raw[HOUR_SLOT] = hour;
    if (hour !== raw[HOUR_SLOT]) {
      pushHour(raw, raw[HOUR_BYTES]);
      raw[HOUR_SLOT] = hour;
      raw[HOUR_BYTES] = 0;
    }
    if (Number.isNaN(raw[DAY_SLOT])) raw[DAY_SLOT] = day;
    if (day !== raw[DAY_SLOT]) {
      rememberDay(dev);
      raw[DAY_SLOT] = day;
      raw[DAY_BYTES] = 0;
    }
    raw[HOUR_BYTES] += ev.bytesOut || 0;
    raw[DAY_BYTES] += ev.bytesOut || 0;
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const raw = dev.raw;
    if (!countable(ev) || raw[FIRED] === 1) return;
    if (raw[FLUSHED] !== 1) {
      raw[FLUSHED] = 1;
      if (!Number.isNaN(raw[HOUR_SLOT])) pushHour(raw, raw[HOUR_BYTES]);
      if (!Number.isNaN(raw[DAY_SLOT])) rememberDay(dev);
    }
    if (raw[COUNT] < 2) return;
    const sigma = Math.sqrt(raw[M2] / (raw[COUNT] - 1));
    const limit = sigma > 0 ? 8 * sigma : 1;
    if (!dev.daily || dev.daily.count < 1) return;
    const bar = 1.5 * quantile(dev.daily);
    const rows = ctx.horizon(dev).last(24);
    let total = 0;
    for (const row of rows) total += row.bytesOut;
    const cusum = createCusum({ k: 0.5 * sigma, h: limit, mean: raw[MEAN] });
    for (const row of rows) pushCusum(cusum, row.bytesOut);
    if (!cusum.alarmed || !(total > bar)) return;
    raw[FIRED] = 1;
    return {
      severity: ctx.options.severity,
      ts: ev.ts,
      explain: explainThreshold({
        test: 'gt',
        observed: total,
        threshold: bar,
        formula: '24 h bytesOut > 1.5 × learned daily p99, and Page CUSUM h = 8σ',
        learned: { mean: raw[MEAN], sigma, h: limit },
      }),
      data: { total, bar, sigma, h: limit, cusum: cusum.high },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    const raw = dev.raw;
    return {
      hourly: {
        count: raw[COUNT],
        mean: raw[MEAN],
        m2: raw[M2],
        min: raw[MIN],
        max: raw[MAX],
      },
      daily: dev.daily ? toJSON(dev.daily) : null,
      hour: Number.isNaN(raw[HOUR_SLOT]) ? null : raw[HOUR_SLOT],
      hourBytes: raw[HOUR_BYTES],
      day: Number.isNaN(raw[DAY_SLOT]) ? null : raw[DAY_SLOT],
      dayBytes: raw[DAY_BYTES],
      flushed: raw[FLUSHED] === 1,
      fired: raw[FIRED] === 1,
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    assertState(state, detector.id);
    const raw = dev.raw;
    raw.fill(0);
    raw[HOUR_SLOT] = NaN;
    raw[DAY_SLOT] = NaN;
    if (state.hourly && typeof state.hourly === 'object') {
      raw[COUNT] = state.hourly.count || 0;
      raw[MEAN] = state.hourly.mean || 0;
      raw[M2] = state.hourly.m2 || 0;
      raw[MIN] = Number.isFinite(state.hourly.min) ? state.hourly.min : 0;
      raw[MAX] = Number.isFinite(state.hourly.max) ? state.hourly.max : 0;
    }
    dev.daily = null;
    if (state.daily && typeof state.daily === 'object') dev.daily = fromJSON(state.daily);
    raw[HOUR_SLOT] = typeof state.hour === 'number' ? state.hour : NaN;
    raw[HOUR_BYTES] = state.hourBytes || 0;
    raw[DAY_SLOT] = typeof state.day === 'number' ? state.day : NaN;
    raw[DAY_BYTES] = state.dayBytes || 0;
    raw[FLUSHED] = state.flushed ? 1 : 0;
    raw[FIRED] = state.fired ? 1 : 0;
  },
};

/** @returns {{ raw: Float64Array, daily: any }} */
function blank() {
  const raw = new Float64Array(11);
  raw[HOUR_SLOT] = NaN;
  raw[DAY_SLOT] = NaN;
  return { raw, daily: null };
}

/**
 * @param {Float64Array} raw
 * @param {number} value
 */
function pushHour(raw, value) {
  const stats = {
    count: raw[COUNT],
    mean: raw[MEAN],
    m2: raw[M2],
    min: raw[MIN],
    max: raw[MAX],
  };
  if (stats.count === 0) {
    raw[COUNT] = 1;
    raw[MEAN] = value;
    raw[M2] = 0;
    raw[MIN] = value;
    raw[MAX] = value;
    return;
  }
  push(stats, value);
  raw[COUNT] = stats.count;
  raw[MEAN] = stats.mean;
  raw[M2] = stats.m2;
  raw[MIN] = stats.min;
  raw[MAX] = stats.max;
}

/**
 * @param {any} dev
 */
function rememberDay(dev) {
  const stats = dev.daily || createP2(0.99);
  pushP2(stats, dev.raw[DAY_BYTES]);
  dev.daily = stats;
}

/**
 * @param {any} ev
 */
function countable(ev) {
  return ev && ev.type === 'flow' && typeof ev.dstIp === 'string' && !isGroupDst(ev.dstIp);
}

module.exports = detector;
