'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings, fillSet } = require('./state');
const { isGroupDst } = require('./lib');

const detector = {
  id: 'lan-lateral',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Low on IoT (devices rarely talk east-west except hub ↔ device)',
    stage: 'spread',
  },
  requires: ['T1'],
  category: 'scan',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { peers: new LruSet(caps.maxDestinations), alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {string} kind @param {string} value */
  allow(dev, kind, value) {
    if (kind !== 'peer') return false;
    dev.peers.add(value);
    return true;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'flow' && ev.direction === 'lan' && ev.dstIp && !isGroupDst(ev.dstIp)) {
      dev.peers.add(ev.dstIp);
    }
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'lan' || !ev.dstIp || isGroupDst(ev.dstIp)) return;
    if (dev.peers.has(ev.dstIp) || dev.alerted.has(ev.dstIp)) return;
    dev.alerted.add(ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.84,
      ts: ev.ts,
      actual: ev.dstIp,
      expected: `${dev.peers.size} known LAN peers`,
      data: { peer: ev.dstIp },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { peers: dev.peers.toArray(), alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.peers = fillSet(
      readStrings(state.peers, caps.maxDestinations, caps.maxString, 'peers'),
      caps.maxDestinations,
    );
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return (dev.peers.size + dev.alerted.size) * 32;
  },
};

module.exports = detector;
