'use strict';

const { HubvikError } = require('../errors');

const { isPublic } = require('../engine/net');
const { assertState } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const detector = {
  id: 'dispersed-flood',
  version: 1,
  meta: {
    rel: '1.6',
    mode: 'shadow',
    fpRisk: 'Low. Two-way sessions and a single hot destination stay with egress-flood',
    consumes: ['flow'],
    explains: true,
    attack: ['T1498'],
    stage: 'impact',
  },
  requires: ['T1'],
  category: 'volume',
  hardRule: false,
  defaults: {
    enabled: true,
    severity: 'high',
    minDestinations: 8,
    minPktsEach: 200,
    maxPktsEach: 50000,
    maxBytesEach: 200000000,
    minTotalPkts: 8000,
    minTotalBytes: 8000000,
    maxRatio: 0.05,
  },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return { win: null, rows: new Map(), fired: false, cap: caps.maxDestinations };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out') return;
    if (typeof ev.dstIp !== 'string' || !isPublic(ev.dstIp) || isGroupDst(ev.dstIp)) return;
    const start = ctx.window ? ctx.window.start : 0;
    if (dev.win !== start) {
      dev.win = start;
      dev.rows = new Map();
      dev.fired = false;
    }
    let row = dev.rows.get(ev.dstIp);
    if (!row) {
      if (dev.rows.size >= dev.cap) return;
      row = { pkts: 0, out: 0, inn: 0 };
      dev.rows.set(ev.dstIp, row);
    }
    row.pkts += ev.pktsOut || 0;
    row.out += ev.bytesOut || 0;
    row.inn += ev.bytesIn || 0;
    if (dev.fired) return;
    const opts = ctx.options;
    let destinations = 0;
    let pkts = 0;
    let bytes = 0;
    for (const item of dev.rows.values()) {
      if (!qualifies(item, opts)) continue;
      destinations += 1;
      pkts += item.pkts;
      bytes += item.out;
    }
    if (destinations < opts.minDestinations) return;
    if (pkts < opts.minTotalPkts && bytes < opts.minTotalBytes) return;
    dev.fired = true;
    const observed = pkts >= opts.minTotalPkts ? pkts : bytes;
    const threshold = pkts >= opts.minTotalPkts ? opts.minTotalPkts : opts.minTotalBytes;
    return {
      severity: opts.severity,
      confidence: 0.86,
      ts: ev.ts,
      actual: `${destinations} one-way destinations, ${pkts} packets, ${bytes} bytes`,
      expected: `under ${opts.minDestinations} destinations or under both totals`,
      explain: explainThreshold({
        test: 'gte',
        observed,
        threshold,
        formula: 'minDestinations and (minTotalPkts or minTotalBytes), each under egress-flood',
        learned: { destinations },
      }),
      data: { destinations, packets: pkts, bytes },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    /** @type {{ ip: string, pkts: number, out: number, inn: number }[]} */
    const rows = [];
    for (const [ip, row] of dev.rows) rows.push({ ip, pkts: row.pkts, out: row.out, inn: row.inn });
    return { win: dev.win, fired: dev.fired, rows };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.cap = caps.maxDestinations;
    dev.win = typeof state.win === 'number' ? state.win : null;
    dev.fired = Boolean(state.fired);
    dev.rows = new Map();
    if (state.rows == null) return;
    if (!Array.isArray(state.rows))
      throw new HubvikError('MUST_BE_AN_ARRAY', 'rows must be an array');
    if (state.rows.length > caps.maxDestinations)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array rows exceeds cap');
    for (const row of state.rows) {
      if (!row || typeof row !== 'object' || Array.isArray(row))
        throw new HubvikError('STATE_IS_INVALID', 'dispersed-flood row is invalid');
      assertState(row, detector.id);
      if (typeof row.ip !== 'string')
        throw new HubvikError('MUST_BE_STRINGS', 'rows ip must be a string');
      if (row.ip.length > caps.maxString)
        throw new HubvikError('STRING_TOO_LONG', 'string too long');
      dev.rows.set(row.ip, {
        pkts: numberOrZero(row.pkts),
        out: numberOrZero(row.out),
        inn: numberOrZero(row.inn),
      });
    }
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    return 64 + dev.rows.size * 48;
  },
};

/**
 * One-way, and still under the per-destination floors `egress-flood` already owns.
 * @param {{ pkts: number, out: number, inn: number }} row
 * @param {any} opts
 * @returns {boolean}
 */
function qualifies(row, opts) {
  if (!(row.out > 0) || row.inn / row.out >= opts.maxRatio) return false;
  if (row.pkts < opts.minPktsEach || row.pkts >= opts.maxPktsEach) return false;
  if (row.out >= opts.maxBytesEach) return false;
  return true;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function numberOrZero(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
}

module.exports = detector;
