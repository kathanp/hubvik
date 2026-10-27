'use strict';

const { HubvikError } = require('../errors');

const { isPublic } = require('../engine/net');
const { assertState } = require('./state');
const { explainThreshold } = require('./lib');

const detector = {
  id: 'egress-flood',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.5',
    fpRisk: 'Low. Camera upload is ~15 MB/window and two-way TCP',
    explains: true,
    attack: ['T1498'],
    stage: 'impact',
    dedupGroup: 'flood',
  },
  requires: ['T1'],
  category: 'volume',
  hardRule: true,
  defaults: {
    minPkts: 50_000,
    minBytesOut: 200_000_000,
    watchFactor: 10,
    watchFloor: 5_000,
    maxRatio: 0.05,
    severity: 'critical',
  },

  /** @param {any} caps */
  createState(caps) {
    return { win: null, rows: new Map(), learned: new Map(), cap: caps.maxDestinations };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || typeof ev.dstIp !== 'string' || !isPublic(ev.dstIp)) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      if (ctx.learning) remember(dev);
      dev.win = start;
      dev.rows = new Map();
    }
    let row = dev.rows.get(ev.dstIp);
    if (!row) {
      if (dev.rows.size >= dev.cap) return;
      row = { pkts: 0, out: 0, inn: 0, fired: false };
      dev.rows.set(ev.dstIp, row);
    }
    row.pkts += ev.pktsOut || 0;
    row.out += ev.bytesOut || 0;
    row.inn += ev.bytesIn || 0;
    if (row.fired) {
      noteFlood(ctx, ev.dstIp);
      return;
    }
    if (row.out <= 0 || row.inn / row.out >= ctx.options.maxRatio) return;
    const absolute = row.pkts >= ctx.options.minPkts || row.out >= ctx.options.minBytesOut;
    const learnedMax = dev.learned.get(ev.dstIp) || 0;
    const floor = Math.max(ctx.options.watchFloor, ctx.options.watchFactor * learnedMax);
    const relative = !ctx.learning && row.pkts >= floor;
    if (!absolute && !relative) return;
    row.fired = true;
    noteFlood(ctx, ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${row.pkts} packets and ${row.out} bytes to ${ev.dstIp}`,
      expected: `under ${ctx.options.minPkts} packets and ${ctx.options.minBytesOut} bytes`,
      data: {
        dstIp: ev.dstIp,
        packets: row.pkts,
        bytesOut: row.out,
        bytesPerPacket: row.pkts > 0 ? row.out / row.pkts : 0,
      },
      explain: explainThreshold({
        test: 'gte',
        observed: row.pkts,
        threshold: ctx.options.minPkts,
        formula: `minPkts=${ctx.options.minPkts}`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { learned: dev.learned instanceof Map ? [...dev.learned.entries()] : [] };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.win = null;
    dev.rows = new Map();
    dev.learned = new Map();
    dev.cap = caps.maxDestinations;
    if (state.learned == null) return;
    if (!Array.isArray(state.learned))
      throw new HubvikError('LEARNED_MUST_BE_AN_ARRAY', 'learned must be an array');
    if (state.learned.length > caps.maxDestinations)
      throw new HubvikError('ARRAY_LEARNED_EXCEEDS_CAP', 'array learned exceeds cap');
    for (const pair of state.learned) {
      if (!Array.isArray(pair) || pair.length !== 2)
        throw new HubvikError('LEARNED_MUST_BE_PAIRS', 'learned must be pairs');
      if (typeof pair[0] !== 'string' || typeof pair[1] !== 'number') {
        throw new HubvikError(
          'LEARNED_MUST_BE_A_DESTINATION_AND_A_COUNT',
          'learned must be a destination and a count',
        );
      }
      if (pair[0].length > caps.maxString)
        throw new HubvikError('STRING_TOO_LONG', 'string too long');
      dev.learned.set(pair[0], pair[1]);
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.learned.size * 32 + dev.rows.size * 32;
  },
};

/**
 * Same device window, so stream-to-new-destination can stay quiet for this address.
 * @param {any} ctx
 * @param {string} dstIp
 */
function noteFlood(ctx, dstIp) {
  const win = ctx.window;
  if (!win || typeof dstIp !== 'string') return;
  if (!win.egressDsts) win.egressDsts = new Set();
  win.egressDsts.add(dstIp);
}

/**
 * @param {any} dev
 */
function remember(dev) {
  for (const [ip, row] of dev.rows) {
    if (row.fired) continue;
    const prev = dev.learned.get(ip) || 0;
    if (row.pkts > prev && dev.learned.size < dev.cap) dev.learned.set(ip, row.pkts);
  }
}

module.exports = detector;
