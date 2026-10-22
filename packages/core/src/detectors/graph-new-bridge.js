'use strict';

const { HubvikError } = require('../errors');

const { zoneOf } = require('../engine/graph');
const { explainNewMember } = require('./lib');

const detector = {
  id: 'graph-new-bridge',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['flow'],
    explains: true,
  },
  requires: ['T1'],
  category: 'lateral',
  hardRule: false,
  defaults: { enabled: true, severity: 'high' },

  /** @param {any} _ev @param {any} ctx */
  prepare(_ev, ctx) {
    const zones = ctx.zones || [];
    return zones.length > 0 && Boolean(ctx.lanEdges);
  },

  createState() {
    return { pairs: new Set(), fired: false };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  learn(dev, ev, ctx) {
    for (const pair of pairsOf(ctx)) {
      dev.pairs.add(pair);
      if (ctx.bridges) ctx.bridges.add(pair);
    }
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const zones = ctx.zones || [];
    if (zones.length === 0 || dev.fired) return;
    for (const pair of pairsOf(ctx)) {
      if (dev.pairs.has(pair)) continue;
      const global = ctx.bridges;
      if (global && global.has(pair)) continue;
      dev.fired = true;
      return {
        severity: ctx.options.severity,
        confidence: 0.8,
        ts: ev.ts,
        actual: pair,
        expected: 'no new zone pair',
        explain: explainNewMember({ observed: pair, learnedCount: dev.pairs.size }),
        data: { pair },
      };
    }
  },

  /** @param {any} dev */
  exportState(dev) {
    return { pairs: [...dev.pairs], fired: dev.fired };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.pairs = new Set();
    dev.fired = Boolean(state && state.fired);
    if (!state || !Array.isArray(state.pairs)) return;
    if (state.pairs.length > 256)
      throw new HubvikError('ARRAY_PAIRS_EXCEEDS_CAP', 'array pairs exceeds cap');
    for (const pair of state.pairs) dev.pairs.add(String(pair));
  },
};

/**
 * @param {any} ctx
 * @returns {string[]}
 */
function pairsOf(ctx) {
  const zones = ctx.zones || [];
  if (zones.length === 0 || !ctx.lanEdges) return [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const row of ctx.lanEdges.values()) {
    const zone = zoneOf(zones, row.dstIp);
    if (zone) seen.add(zone);
  }
  const ids = [...seen].sort();
  /** @type {string[]} */
  const pairs = [];
  for (let i = 0; i < ids.length; i += 1) {
    for (let j = i + 1; j < ids.length; j += 1) pairs.push(`${ids[i]}|${ids[j]}`);
  }
  return pairs;
}

module.exports = detector;
