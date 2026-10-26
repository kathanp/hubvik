'use strict';

const { isPublic } = require('../engine/net');
const { assertState, readStrings } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const detector = {
  id: 'proxy-fanin',
  version: 1,
  meta: {
    rel: '2.0',
    mode: 'shadow',
    fpRisk: 'Low. A learned inbound peer does not count, and a scan has no two-way bytes',
    consumes: ['flow'],
    explains: true,
    attack: ['T1090'],
    stage: 'impact',
  },
  requires: ['T1'],
  category: 'proxy',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minPeers: 8 },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return {
      learned: new Set(),
      win: null,
      peers: new Set(),
      fired: false,
      cap: caps.maxDestinations,
    };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const ip = relaySrc(ev);
    if (!ip || dev.learned.has(ip) || dev.learned.size >= dev.cap) return;
    dev.learned.add(ip);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const ip = relaySrc(ev);
    if (!ip || dev.learned.has(ip)) return;
    const start = ctx.window ? ctx.window.start : 0;
    if (dev.win !== start) {
      dev.win = start;
      dev.peers = new Set();
      dev.fired = false;
    }
    if (!dev.peers.has(ip)) {
      if (dev.peers.size >= dev.cap) return;
      dev.peers.add(ip);
    }
    if (dev.fired || dev.peers.size < ctx.options.minPeers) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.86,
      ts: ev.ts,
      actual: `${dev.peers.size} new public clients`,
      expected: `under ${ctx.options.minPeers} established two-way inbound sessions`,
      explain: explainThreshold({
        test: 'gte',
        observed: dev.peers.size,
        threshold: ctx.options.minPeers,
        formula: 'public established inbound sessions, both byte directions, dstPort > 1024',
      }),
      data: { peers: dev.peers.size },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    return { learned: [...dev.learned], win: dev.win, fired: dev.fired, peers: [...dev.peers] };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.cap = caps.maxDestinations;
    dev.learned = new Set(
      readStrings(state.learned, caps.maxDestinations, caps.maxString, 'learned'),
    );
    dev.win = typeof state.win === 'number' ? state.win : null;
    dev.fired = Boolean(state.fired);
    dev.peers = new Set(readStrings(state.peers, caps.maxDestinations, caps.maxString, 'peers'));
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    return 64 + (dev.learned.size + dev.peers.size) * 48;
  },
};

/**
 * Public client of an established two-way session to a high port.
 * `p2p-pattern` wants 30 peers of either direction. `inbound-from-wan` fires on one session.
 * @param {any} ev
 * @returns {string | null}
 */
function relaySrc(ev) {
  if (!ev || ev.type !== 'flow' || ev.direction !== 'in' || ev.proto !== 'tcp') return null;
  if (ev.tcpOutcome !== 'established') return null;
  if (!(ev.dstPort > 1024)) return null;
  if (!(ev.bytesOut > 0) || !(ev.bytesIn > 0)) return null;
  if (typeof ev.srcIp !== 'string' || !isPublic(ev.srcIp) || isGroupDst(ev.srcIp)) return null;
  return ev.srcIp;
}

module.exports = detector;
