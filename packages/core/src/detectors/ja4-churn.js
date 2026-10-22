'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');

const detector = {
  id: 'ja4-churn',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low on single-stack IoT',
    consumes: ['tls'],
    attack: ['T1027'],
  },
  requires: ['T3'],
  category: 'tls',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { max: 0, win: null, rows: new Map(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    note(dev, ev, ctx, true);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired) return;
    if (ctx.deviceClass && ctx.deviceClass.allowsBrowserJa4) return;
    const size = note(dev, ev, ctx, false);
    if (dev.max > 1 || size < 4) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${size} JA4 strings to ${ev.dstIp}`,
      expected: 'at most one JA4 per destination in a window',
      data: { dstIp: ev.dstIp, sni: ev.sni || null, count: size },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { max: dev.max, fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.max = 0;
    dev.win = null;
    dev.rows = new Map();
    dev.fired = Boolean(state && state.fired);
    if (state && Number.isInteger(state.max)) {
      if (state.max > 10000) throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array max exceeds cap');
      dev.max = state.max;
    }
  },

  memoryEstimate() {
    return 64;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 * @param {boolean} learning
 * @returns {number}
 */
function note(dev, ev, ctx, learning) {
  if (!ev || ev.type !== 'tls' || !ev.ja4 || !ev.dstIp) return 0;
  const start = ctx.window && ctx.window.start;
  if (dev.win !== start) {
    dev.win = start;
    dev.rows = new Map();
  }
  const key = `${ev.dstIp}|${ev.sni || ''}`;
  let set = dev.rows.get(key);
  if (!set) {
    if (dev.rows.size >= 256) return 0;
    set = new Set();
    dev.rows.set(key, set);
  }
  if (set.size < 32) set.add(ev.ja4);
  if (learning && set.size > dev.max) dev.max = set.size;
  return set.size;
}

module.exports = detector;
