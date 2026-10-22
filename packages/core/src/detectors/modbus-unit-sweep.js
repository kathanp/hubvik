'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');

const detector = {
  id: 'modbus-unit-sweep',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['app'],
    attack: ['T0846'],
  },
  requires: ['T5'],
  category: 'ot',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { max: 0, win: null, rows: new Map(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    const size = note(dev, ev, ctx);
    if (size > dev.max) dev.max = size;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired) return;
    const size = note(dev, ev, ctx);
    if (dev.max > 2 || size < 16) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${size} unit ids on ${ev.peerIp}`,
      expected: 'at most 2 unit ids for this client',
      data: { peerIp: ev.peerIp, units: size },
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
      if (state.max > 256) throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array max exceeds cap');
      dev.max = state.max;
    }
  },

  memoryEstimate() {
    return 32;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 * @returns {number}
 */
function note(dev, ev, ctx) {
  if (!ev || ev.type !== 'app' || ev.proto !== 'modbus' || !Number.isInteger(ev.unitId)) return 0;
  const start = ctx.window && ctx.window.start;
  if (dev.win !== start) {
    dev.win = start;
    dev.rows = new Map();
  }
  const key = ev.peerIp;
  let set = dev.rows.get(key);
  if (!set) {
    if (dev.rows.size >= 64) return 0;
    set = new Set();
    dev.rows.set(key, set);
  }
  if (set.size < 256) set.add(ev.unitId);
  return set.size;
}

module.exports = detector;
