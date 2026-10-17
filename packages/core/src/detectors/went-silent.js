'use strict';

const HOUR = 3600e3;

/**
 * True when a learned active hour sits strictly between two timestamps.
 * @param {Set<number>} hours
 * @param {number} from
 * @param {number} to
 * @returns {boolean}
 */
function skippedActive(hours, from, to) {
  if (hours.size === 0 || to <= from + HOUR) return false;
  const span = Math.floor((to - from) / HOUR);
  if (span > 48) return true;
  for (let i = 1; i < span; i++) {
    if (hours.has(new Date(from + i * HOUR).getUTCHours())) return true;
  }
  return false;
}

const detector = {
  id: 'went-silent',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Medium',
  },
  requires: ['T0'],
  category: 'timing',
  defaults: { factor: 3, sessionMs: 6 * HOUR, severity: 'medium' },

  createState() {
    return { hours: new Set(), maxGap: 0, lastTs: null, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    note(dev, ev, ctx, false);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    note(dev, ev, ctx, true);
  },

  /**
   * Alert once while watching when now is inside a learned active hour.
   * @param {any} dev
   * @param {any} ctx
   */
  tick(dev, ctx) {
    if (dev.fired || dev.lastTs == null || !(dev.maxGap > 0)) return;
    const now = ctx.ts;
    if (!dev.hours.has(ctx.hour(now))) return;
    const gap = now - dev.lastTs;
    if (gap <= dev.maxGap * ctx.options.factor) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: now,
      actual: `silent for ${spanLabel(gap)}`,
      expected: `gaps <= ${spanLabel(dev.maxGap * ctx.options.factor)} during active hours`,
      data: { gapMs: gap, maxGap: dev.maxGap },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      hours: [...dev.hours].sort((a, b) => a - b),
      maxGap: dev.maxGap,
      lastTs: dev.lastTs,
      fired: dev.fired,
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    if (!state || !Array.isArray(state.hours)) throw new Error('hours must be an array');
    if (state.hours.length > 64) throw new Error('array hours exceeds cap');
    dev.hours = new Set();
    for (const hour of state.hours) {
      if (!Number.isInteger(hour) || hour < 0 || hour > 23) throw new Error('hours must be 0..23');
      dev.hours.add(hour);
    }
    if (typeof state.maxGap !== 'number' || state.maxGap < 0) throw new Error('maxGap is invalid');
    dev.maxGap = state.maxGap;
    dev.lastTs = typeof state.lastTs === 'number' ? state.lastTs : null;
    dev.fired = Boolean(state.fired);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.hours.size * 8 + 32;
  },
};

/**
 * @param {number} ms
 * @returns {string}
 */
function spanLabel(ms) {
  if (ms < HOUR) return `${Math.max(1, Math.round(ms / 60000))}min`;
  return `${Math.round(ms / HOUR)}h`;
}

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 * @param {boolean} watching
 */
function note(dev, ev, ctx, watching) {
  const hour = ctx.hour(ev.ts);
  if (!watching && dev.lastTs != null) {
    const gap = ev.ts - dev.lastTs;
    const skipped = skippedActive(dev.hours, dev.lastTs, ev.ts);
    if (!skipped && gap > 0 && gap <= ctx.options.sessionMs) {
      dev.maxGap = Math.max(dev.maxGap, gap);
    }
  }
  if (dev.hours.size < 64) dev.hours.add(hour);
  dev.lastTs = ev.ts;
  dev.fired = false;
}

module.exports = detector;
