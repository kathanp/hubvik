'use strict';

const { HubvikError } = require('../errors');

const { isPublic, isBogon } = require('../engine/net');
const { assertState, readStrings } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const detector = {
  id: 'inbound-lateral',
  version: 1,
  meta: {
    rel: '1.6',
    mode: 'shadow',
    fpRisk: 'Low. Hubs and cameras that already talk on the LAN are learned',
    consumes: ['flow'],
    explains: true,
    attack: ['T1021'],
    stage: 'spread',
  },
  requires: ['T1'],
  category: 'scan',
  hardRule: false,
  defaults: {
    enabled: true,
    severity: 'high',
    followMs: 300000,
    minPeers: 3,
    maxInbound: 8,
  },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return {
      learned: new Set(),
      inbound: [],
      peers: new Set(),
      peerSince: null,
      fired: false,
      cap: caps.maxDestinations,
    };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const peer = lanPeer(ev);
    if (!peer || dev.learned.size >= dev.cap) return;
    dev.learned.add(peer);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow') return;
    if (isInbound(ev)) {
      dev.inbound.push({ src: ev.srcIp, ts: ev.ts });
      const max = ctx.options.maxInbound;
      while (dev.inbound.length > max) dev.inbound.shift();
    }
    const peer = lanPeer(ev);
    if (!peer || dev.learned.has(peer) || dev.fired) return;
    const follow = ctx.options.followMs;
    const live = dev.inbound.some(
      (/** @type {{ src: string, ts: number }} */ row) =>
        ev.ts - row.ts >= 0 && ev.ts - row.ts <= follow,
    );
    if (!live) return;
    if (dev.peerSince == null || ev.ts - dev.peerSince > follow) {
      dev.peers = new Set();
      dev.peerSince = ev.ts;
    }
    if (dev.peers.size >= dev.cap) return;
    dev.peers.add(peer);
    if (dev.peers.size < ctx.options.minPeers) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.87,
      ts: ev.ts,
      actual: `${dev.peers.size} new LAN peers after a public inbound session`,
      expected: `under ${ctx.options.minPeers} new peers inside ${follow} ms`,
      explain: explainThreshold({
        test: 'gte',
        observed: dev.peers.size,
        threshold: ctx.options.minPeers,
        formula: 'public established inbound, then unlearned LAN peers',
      }),
      data: { peers: [...dev.peers], followMs: follow },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    return {
      learned: [...dev.learned],
      inbound: dev.inbound.map((/** @type {{ src: string, ts: number }} */ row) => ({
        src: row.src,
        ts: row.ts,
      })),
      peers: [...dev.peers],
      peerSince: dev.peerSince,
      fired: dev.fired,
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.cap = caps.maxDestinations;
    const learned = readStrings(state.learned, caps.maxDestinations, caps.maxString, 'learned');
    const peers = readStrings(state.peers, caps.maxDestinations, caps.maxString, 'peers');
    dev.learned = new Set(learned);
    dev.peers = new Set(peers);
    dev.peerSince = typeof state.peerSince === 'number' ? state.peerSince : null;
    dev.fired = Boolean(state.fired);
    dev.inbound = [];
    if (state.inbound == null) return;
    if (!Array.isArray(state.inbound))
      throw new HubvikError('MUST_BE_AN_ARRAY', 'inbound must be an array');
    if (state.inbound.length > detector.defaults.maxInbound)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array inbound exceeds cap');
    for (const row of state.inbound) {
      if (!row || typeof row.src !== 'string' || typeof row.ts !== 'number')
        throw new HubvikError('STATE_IS_INVALID', 'inbound-lateral row is invalid');
      if (row.src.length > caps.maxString)
        throw new HubvikError('STRING_TOO_LONG', 'string too long');
      dev.inbound.push({ src: row.src, ts: row.ts });
    }
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    return 96 + (dev.learned.size + dev.peers.size + dev.inbound.length) * 40;
  },
};

/**
 * @param {any} ev
 * @returns {boolean}
 */
function isInbound(ev) {
  return (
    ev.direction === 'in' &&
    ev.tcpOutcome === 'established' &&
    typeof ev.srcIp === 'string' &&
    isPublic(ev.srcIp)
  );
}

/**
 * A unicast LAN peer. Group addresses and public destinations are not peers.
 * @param {any} ev
 * @returns {string | null}
 */
function lanPeer(ev) {
  if (!ev || ev.type !== 'flow' || ev.direction !== 'lan') return null;
  if (typeof ev.dstIp !== 'string' || isGroupDst(ev.dstIp) || !isBogon(ev.dstIp)) return null;
  if (isPublic(ev.dstIp)) return null;
  return ev.dstIp;
}

module.exports = detector;
