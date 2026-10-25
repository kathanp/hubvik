'use strict';

const { HubvikError } = require('../errors');

const { isPublic } = require('../engine/net');
const { assertState, readStrings } = require('./state');
const { isGroupDst, explainThreshold } = require('./lib');

const detector = {
  id: 'scatter-udp',
  version: 1,
  meta: {
    rel: '2.0',
    mode: 'shadow',
    fpRisk: 'Low. DNS, NTP, and a destination at 200 packets stay with the other rows',
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
    minDestinations: 40,
    minPktsEach: 20,
    maxPktsEach: 200,
    maxRatio: 0.05,
    minTotalPkts: 800,
  },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return {
      learned: new Set(),
      win: null,
      rows: new Map(),
      fired: false,
      cap: caps.maxDestinations,
    };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const ip = udpDest(ev);
    if (!ip || dev.learned.has(ip) || dev.learned.size >= dev.cap) return;
    dev.learned.add(ip);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const ip = udpDest(ev);
    if (!ip || dev.learned.has(ip)) return;
    const start = ctx.window ? ctx.window.start : 0;
    if (dev.win !== start) {
      dev.win = start;
      dev.rows = new Map();
      dev.fired = false;
    }
    let row = dev.rows.get(ip);
    if (!row) {
      if (dev.rows.size >= dev.cap) return;
      row = { pkts: 0, out: 0, inn: 0 };
      dev.rows.set(ip, row);
    }
    row.pkts += ev.pktsOut || 0;
    row.out += ev.bytesOut || 0;
    row.inn += ev.bytesIn || 0;
    if (dev.fired) return;
    const opts = ctx.options;
    let destinations = 0;
    let pkts = 0;
    for (const item of dev.rows.values()) {
      if (!qualifies(item, opts)) continue;
      destinations += 1;
      pkts += item.pkts;
    }
    if (destinations < opts.minDestinations || pkts < opts.minTotalPkts) return;
    dev.fired = true;
    return {
      severity: opts.severity,
      confidence: 0.84,
      ts: ev.ts,
      actual: `${destinations} UDP destinations, ${pkts} packets`,
      expected: `under ${opts.minDestinations} destinations or under ${opts.minTotalPkts} packets`,
      explain: explainThreshold({
        test: 'gte',
        observed: pkts,
        threshold: opts.minTotalPkts,
        formula: '40 destinations in the 20-to-199 packet band, total at least 800',
        learned: { destinations },
      }),
      data: { destinations, packets: pkts },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    /** @type {{ ip: string, pkts: number, out: number, inn: number }[]} */
    const rows = [];
    for (const [ip, row] of dev.rows) rows.push({ ip, pkts: row.pkts, out: row.out, inn: row.inn });
    return { learned: [...dev.learned], win: dev.win, fired: dev.fired, rows };
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
    dev.rows = new Map();
    if (state.rows == null) return;
    if (!Array.isArray(state.rows))
      throw new HubvikError('MUST_BE_AN_ARRAY', 'rows must be an array');
    if (state.rows.length > caps.maxDestinations)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array rows exceeds cap');
    for (const row of state.rows) {
      if (!row || typeof row !== 'object' || Array.isArray(row))
        throw new HubvikError('STATE_IS_INVALID', 'scatter-udp row is invalid');
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
    return 64 + (dev.learned.size + dev.rows.size) * 48;
  },
};

/**
 * Public UDP destination that is not DNS or NTP.
 * A destination that reaches 200 packets belongs to `dispersed-flood`.
 * @param {any} ev
 * @returns {string | null}
 */
function udpDest(ev) {
  if (!ev || ev.type !== 'flow' || ev.direction !== 'out' || ev.proto !== 'udp') return null;
  if (ev.dstPort === 53 || ev.dstPort === 123) return null;
  if (typeof ev.dstIp !== 'string' || !isPublic(ev.dstIp) || isGroupDst(ev.dstIp)) return null;
  return ev.dstIp;
}

/**
 * One-way, and still under the per-destination packet floor of `dispersed-flood`.
 * @param {{ pkts: number, out: number, inn: number }} row
 * @param {any} opts
 * @returns {boolean}
 */
function qualifies(row, opts) {
  if (!(row.out > 0) || row.inn / row.out >= opts.maxRatio) return false;
  if (row.pkts < opts.minPktsEach || row.pkts >= opts.maxPktsEach) return false;
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
