'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');

const HOUR = 60 * 60 * 1000;
const SIX_H = 6 * HOUR;

const detector = {
  id: 'suppression-abuse',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Medium after a large initial tuning session; that is why it is medium',
    consumes: ['summary'],
    attack: ['T1562.001'],
  },
  requires: ['T0'],
  category: 'integrity',
  hardRule: false,
  defaults: { severity: 'medium' },

  createState() {
    return { fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || !Array.isArray(ctx.abuseFacts) || ctx.abuseFacts.length === 0) return;
    const facts = ctx.abuseFacts.filter((/** @type {any} */ row) => ev.ts - row.ts <= HOUR);
    /** @type {Map<string, number>} */
    const calls = new Map();
    let hard = false;
    let wide = false;
    const annotated = new Set();
    for (const row of facts) {
      const who = row.operator || 'unknown';
      if (row.kind === 'allow' || row.kind === 'suppress') {
        calls.set(who, (calls.get(who) || 0) + 1);
      }
      if (row.kind === 'suppress' && row.detectorId && isHard(row.detectorId)) hard = true;
      if (
        row.kind === 'annotate' &&
        typeof row.untilTs === 'number' &&
        typeof row.fromTs === 'number' &&
        row.untilTs - row.fromTs > SIX_H
      ) {
        if (row.target === '*') wide = true;
        else annotated.add(row.target);
      }
    }
    const half =
      ctx.deviceCount > 0 && annotated.size / ctx.deviceCount >= 0.5 && annotated.size > 0;
    const burst = [...calls.values()].some((count) => count >= 20);
    if (!burst && !hard && !wide && !half) return;
    dev.fired = true;
    return {
      device: '__engine__',
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: 'operator actions silenced detection',
      expected: 'fewer than 20 allow or suppress calls an hour, and no hard-rule suppress',
      data: { burst, hard, wide },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = Boolean(state && state.fired);
    if (state && Array.isArray(state.extra) && state.extra.length > 20) {
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array extra exceeds cap');
    }
  },

  memoryEstimate() {
    return 8;
  },
};

/**
 * @param {string} id
 * @returns {boolean}
 */
function isHard(id) {
  const { BY_ID } = require('./index');
  const det = BY_ID[id];
  return Boolean(det && det.hardRule);
}

module.exports = detector;
