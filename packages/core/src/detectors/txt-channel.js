'use strict';

const { HubvikError } = require('../errors');

const { assertState, readStrings } = require('./state');
const { explainThreshold } = require('./lib');

const CAP = 64;

const detector = {
  id: 'txt-channel',
  version: 1,
  meta: {
    rel: '1.6',
    mode: 'shadow',
    fpRisk: 'Low. A single TXT lookup and a long label stay with dns-tunnel',
    consumes: ['dns'],
    explains: true,
    attack: ['T1071.004'],
    stage: 'c2',
  },
  requires: ['T2'],
  category: 'dns',
  hardRule: false,
  defaults: {
    enabled: true,
    severity: 'high',
    minQueries: 12,
    minLabel: 20,
    maxLabel: 40,
  },

  createState() {
    return { learned: new Set(), win: null, counts: new Map(), fired: new Set() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  learn(dev, ev, ctx) {
    const name = channelName(ev, ctx.options);
    if (!name || dev.learned.size >= CAP) return;
    dev.learned.add(name);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const name = channelName(ev, ctx.options);
    if (!name || dev.learned.has(name)) return;
    const start = ctx.window ? ctx.window.start : 0;
    if (dev.win !== start) {
      dev.win = start;
      dev.counts = new Map();
      dev.fired = new Set();
    }
    if (dev.fired.has(name)) return;
    let count = dev.counts.get(name) || 0;
    if (count === 0 && dev.counts.size >= CAP) return;
    count += 1;
    dev.counts.set(name, count);
    if (count < ctx.options.minQueries) return;
    dev.fired.add(name);
    return {
      severity: ctx.options.severity,
      confidence: 0.84,
      ts: ev.ts,
      actual: `${count} TXT or NULL queries for ${name}`,
      expected: `under ${ctx.options.minQueries} queries, or a label dns-tunnel already scores`,
      explain: explainThreshold({
        test: 'gte',
        observed: count,
        threshold: ctx.options.minQueries,
        formula: 'TXT or NULL, label length 20 to 40, name not learned',
      }),
      data: { qname: name, queries: count, qtype: String(ev.qtype).toUpperCase() },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    /** @type {{ name: string, n: number }[]} */
    const counts = [];
    for (const [name, n] of dev.counts) counts.push({ name, n });
    return {
      learned: [...dev.learned],
      win: dev.win,
      counts,
      fired: [...dev.fired],
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    const learned = readStrings(state.learned, CAP, caps.maxString, 'learned');
    const fired = readStrings(state.fired, CAP, caps.maxString, 'fired');
    dev.learned = new Set(learned);
    dev.fired = new Set(fired);
    dev.win = typeof state.win === 'number' ? state.win : null;
    dev.counts = new Map();
    if (state.counts == null) return;
    if (!Array.isArray(state.counts))
      throw new HubvikError('MUST_BE_AN_ARRAY', 'counts must be an array');
    if (state.counts.length > CAP)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array counts exceeds cap');
    for (const row of state.counts) {
      if (!row || typeof row !== 'object' || Array.isArray(row))
        throw new HubvikError('MUST_BE_STRINGS', 'counts name must be a string');
      assertState(row, detector.id);
      if (typeof row.name !== 'string')
        throw new HubvikError('MUST_BE_STRINGS', 'counts name must be a string');
      if (row.name.length > caps.maxString)
        throw new HubvikError('STRING_TOO_LONG', 'string too long');
      dev.counts.set(row.name, numberOrZero(row.n));
    }
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    return 64 + (dev.learned.size + dev.counts.size + dev.fired.size) * 48;
  },
};

/**
 * A TXT or NULL name whose leftmost label is too short for `dns-tunnel`'s long flag.
 * @param {any} ev
 * @param {any} opts
 * @returns {string | null}
 */
function channelName(ev, opts) {
  if (!ev || ev.type !== 'dns' || typeof ev.qname !== 'string') return null;
  const qtype = String(ev.qtype || '').toUpperCase();
  if (qtype !== 'TXT' && qtype !== 'NULL') return null;
  const label = ev.qname.split('.')[0];
  if (label.length < opts.minLabel || label.length > opts.maxLabel) return null;
  return ev.qname.toLowerCase();
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function numberOrZero(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

module.exports = detector;
