'use strict';

const { LruSet } = require('../engine/caps');
const { assertSafeKeys } = require('../engine/validate');

const detector = {
  id: 'new-destination',
  version: 1,
  requires: ['T0'],
  category: 'destination',
  defaults: { maxNewDstPerWindow: 3, severity: 'medium' },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return {
      dsts: new LruSet(caps.maxDestinations),
      alerted: new LruSet(caps.maxAlertKeys),
    };
  },

  /**
   * @param {{ dsts: any, alerted: any }} dev
   * @param {string} kind
   * @param {string} value
   * @returns {boolean}
   */
  allow(dev, kind, value) {
    if (kind !== 'dst') return false;
    dev.dsts.add(value);
    return true;
  },

  /**
   * @param {{ dsts: any }} dev
   * @param {{ dst?: string }} ev
   */
  learn(dev, ev) {
    if (ev.dst) dev.dsts.add(ev.dst);
  },

  /**
   * @param {{ dsts: any, alerted: any }} dev
   * @param {{ dst?: string, ts: number }} ev
   * @param {{ options: { maxNewDstPerWindow: number, severity: string }, window: { newDst: number } }} ctx
   */
  check(dev, ev, ctx) {
    if (!ev.dst || dev.dsts.has(ev.dst) || dev.alerted.has(ev.dst)) return;
    dev.alerted.add(ev.dst);
    ctx.window.newDst += 1;
    if (ctx.window.newDst > ctx.options.maxNewDstPerWindow) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: ev.dst,
      expected: `${dev.dsts.size} known hosts`,
      data: { dst: ev.dst, known: dev.dsts.size },
    };
  },

  /**
   * @param {{ dsts: any, alerted: any }} dev
   */
  exportState(dev) {
    return { dsts: dev.dsts.toArray(), alerted: dev.alerted.toArray() };
  },

  /**
   * @param {{ dsts: any, alerted: any }} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    const next = read(state, caps);
    dev.dsts = next.dsts;
    dev.alerted = next.alerted;
  },

  /**
   * @param {{ dsts: any, alerted: any }} dev
   */
  memoryEstimate(dev) {
    return (dev.dsts.size + dev.alerted.size) * 64 + 64;
  },
};

/**
 * @param {any} state
 * @param {{ maxDestinations: number, maxAlertKeys: number, maxString: number }} caps
 */
function read(state, caps) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new Error('new-destination state is invalid');
  }
  assertSafeKeys(state, 'new-destination');
  const dsts = readNames(state.dsts, caps.maxDestinations, caps.maxString, 'dsts');
  const alerted = readNames(state.alerted ?? [], caps.maxAlertKeys, caps.maxString, 'alerted');
  const dstSet = new LruSet(caps.maxDestinations);
  const alertedSet = new LruSet(caps.maxAlertKeys);
  for (const name of dsts) dstSet.add(name);
  for (const name of alerted) alertedSet.add(name);
  return { dsts: dstSet, alerted: alertedSet };
}

/**
 * @param {unknown} value
 * @param {number} max
 * @param {number} maxString
 * @param {string} label
 * @returns {string[]}
 */
function readNames(value, max, maxString, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  if (value.length > max) throw new Error(`array ${label} exceeds cap`);
  for (const item of value) {
    if (typeof item !== 'string') throw new Error(`${label} must be strings`);
    if (item.length > maxString) throw new Error('string too long');
  }
  return value;
}

module.exports = detector;
