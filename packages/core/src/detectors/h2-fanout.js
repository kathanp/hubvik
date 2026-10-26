'use strict';

const { isPublic } = require('../engine/net');
const { assertState, readStrings } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const detector = {
  id: 'h2-fanout',
  version: 1,
  meta: {
    rel: '2.0',
    mode: 'shadow',
    fpRisk: 'Medium. A device that opens many new HTTP/2 destinations in one window',
    consumes: ['tls'],
    explains: true,
    attack: ['T1498'],
    stage: 'impact',
  },
  requires: ['T3'],
  category: 'volume',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minDestinations: 64 },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return {
      learned: new Set(),
      win: null,
      dests: new Set(),
      fired: false,
      cap: caps.maxDestinations,
    };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const ip = h2Dest(ev);
    if (!ip || dev.learned.has(ip) || dev.learned.size >= dev.cap) return;
    dev.learned.add(ip);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const ip = h2Dest(ev);
    if (!ip || dev.learned.has(ip)) return;
    const start = ctx.window ? ctx.window.start : 0;
    if (dev.win !== start) {
      dev.win = start;
      dev.dests = new Set();
      dev.fired = false;
    }
    if (!dev.dests.has(ip)) {
      if (dev.dests.size >= dev.cap) return;
      dev.dests.add(ip);
    }
    if (dev.fired || dev.dests.size < ctx.options.minDestinations) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.84,
      ts: ev.ts,
      actual: `${dev.dests.size} new HTTP/2 destinations`,
      expected: `under ${ctx.options.minDestinations} new destinations with ALPN h2`,
      explain: explainThreshold({
        test: 'gte',
        observed: dev.dests.size,
        threshold: ctx.options.minDestinations,
        formula: 'distinct public destinations whose TLS ALPN list includes h2',
      }),
      data: { destinations: dev.dests.size, alpn: 'h2' },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    return { learned: [...dev.learned], win: dev.win, fired: dev.fired, dests: [...dev.dests] };
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
    dev.dests = new Set(readStrings(state.dests, caps.maxDestinations, caps.maxString, 'dests'));
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    return 64 + (dev.learned.size + dev.dests.size) * 48;
  },
};

/**
 * Public destination of a TLS handshake that offered HTTP/2.
 * `browser-mimic` needs a host JA4 list and fires on one handshake.
 * This row counts destinations.
 * @param {any} ev
 * @returns {string | null}
 */
function h2Dest(ev) {
  if (!ev || ev.type !== 'tls' || !Array.isArray(ev.alpn) || !ev.alpn.includes('h2')) return null;
  if (typeof ev.dstIp !== 'string' || !isPublic(ev.dstIp) || isGroupDst(ev.dstIp)) return null;
  return ev.dstIp;
}

module.exports = detector;
