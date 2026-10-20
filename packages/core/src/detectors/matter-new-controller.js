'use strict';

const { LruSet } = require('../engine/caps');
const { assertState, readStrings } = require('./state');
const { explainNewMember } = require('./lib');

const OPS = new Set(['AddNOC', 'AddTrustedRootCertificate']);

const detector = {
  id: 'matter-new-controller',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['app'],
    explains: true,
  },
  requires: ['T5'],
  category: 'lateral',
  hardRule: false,
  defaults: { enabled: true, severity: 'high' },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return { peers: new LruSet(caps.maxDestinations), fired: false };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const peer = peerOf(ev);
    if (peer) dev.peers.add(peer);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const peer = peerOf(ev);
    if (!peer || dev.fired || !OPS.has(ev.op)) return;
    if (dev.peers.has(peer)) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${ev.op} from ${peer}`,
      expected: 'controllers learned during setup',
      explain: explainNewMember({ observed: peer, learnedCount: dev.peers.size }),
      data: { op: ev.op, peer },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { peers: dev.peers.toArray(), fired: dev.fired };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.peers = new LruSet(caps.maxDestinations);
    dev.fired = Boolean(state && state.fired);
    for (const peer of readStrings(state.peers, caps.maxDestinations, caps.maxString, 'peers')) {
      dev.peers.add(peer);
    }
  },
};

/**
 * @param {any} ev
 * @returns {string | null}
 */
function peerOf(ev) {
  if (!ev || ev.type !== 'app' || ev.proto !== 'matter') return null;
  if (typeof ev.peerIp === 'string' && ev.peerIp.length > 0) return ev.peerIp;
  return null;
}

module.exports = detector;
