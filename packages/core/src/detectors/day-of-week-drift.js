'use strict';

const { assertState } = require('./state');

const DAY = 86_400_000;
const SPAN = 14 * DAY;

const detector = {
  id: 'day-of-week-drift',
  version: 1,
  meta: {
    rel: '0.9',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: [],
  },
  requires: ['T0'],
  category: 'timing',
  defaults: { enabled: true, severity: 'low' },

  createState() {
    return {
      firstTs: null,
      sum: [0, 0, 0, 0, 0, 0, 0],
      n: [0, 0, 0, 0, 0, 0, 0],
      day: null,
      weekday: 0,
      count: 0,
      fired: null,
    };
  },

  /**
   * @param {any} dev
   * @param {{ start: number, idle?: boolean }} summary
   */
  onWindowClose(dev, summary) {
    if (!summary || summary.idle) return;
    if (dev.firstTs == null) dev.firstTs = summary.start;
    const day = Math.floor(summary.start / DAY);
    const weekday = new Date(summary.start).getUTCDay();
    if (dev.day !== day) {
      if (dev.day != null) {
        dev.sum[dev.weekday] += dev.count;
        dev.n[dev.weekday] += 1;
      }
      dev.day = day;
      dev.weekday = weekday;
      dev.count = 0;
      dev.fired = null;
    }
    dev.count += 1;
    if (summary.start - dev.firstTs < SPAN) return;
    if (dev.fired === day) return;
    const mean = dev.n[weekday] ? dev.sum[weekday] / dev.n[weekday] : 0;
    const high = dev.count >= Math.max(8, 3 * mean);
    const drop = mean >= 8 && dev.count === 0;
    if (!high && !drop) return;
    dev.fired = day;
    return {
      severity: 'low',
      confidence: 0.55,
      ts: summary.start,
      actual: `${dev.count} windows on weekday ${weekday}`,
      expected: `about ${mean} windows`,
      data: { weekday, count: dev.count, mean },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      firstTs: dev.firstTs,
      sum: dev.sum.slice(),
      n: dev.n.slice(),
      day: dev.day,
      weekday: dev.weekday,
      count: dev.count,
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    const next = detector.createState();
    if (Array.isArray(state.sum) && state.sum.length === 7) next.sum = state.sum.map(Number);
    if (Array.isArray(state.n) && state.n.length === 7) next.n = state.n.map(Number);
    next.firstTs = state.firstTs ?? null;
    next.day = state.day ?? null;
    next.weekday = state.weekday || 0;
    next.count = state.count || 0;
    Object.assign(dev, next);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return 128 + (dev.count || 0);
  },
};

module.exports = detector;
