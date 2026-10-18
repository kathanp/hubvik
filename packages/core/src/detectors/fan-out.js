'use strict';

const { emptyStats, pushSample, statsOf } = require('../engine/math');
const { readStreamState } = require('./samples');

const detector = {
  id: 'fan-out',
  version: 1,
  meta: {
    consumes: [
      'summary',
      'flow',
      'dns',
      'tls',
      'http',
      'arp',
      'dhcp',
      'ra',
      'discovery',
      'mapping',
      'app',
    ],
    rel: '0.1',
    fpRisk: 'Low',
    attack: ['T1046'],
    stage: 'recon',
  },
  requires: ['T0'],
  category: 'scan',
  defaults: { minFanout: 10, fanoutFactor: 3, severity: 'high' },

  createState() {
    return { stats: emptyStats(), cachedLimit: null };
  },

  learn() {},

  /**
   * @param {{ stats: { count: number, mean: number, m2: number, max: number }, cachedLimit: number | null }} dev
   * @param {{ ts: number }} ev
   * @param {{ options: { minFanout: number, fanoutFactor: number, severity: string }, window: { dstCount: number, fanoutAlerted: boolean } }} ctx
   */
  check(dev, ev, ctx) {
    const win = ctx.window;
    if (win.fanoutAlerted) return;
    if (dev.cachedLimit == null) {
      const stats = statsOf(dev.stats);
      dev.cachedLimit = Math.max(ctx.options.minFanout, stats.max * ctx.options.fanoutFactor);
    }
    const limit = dev.cachedLimit;
    if (win.dstCount > limit) {
      win.fanoutAlerted = true;
      return {
        severity: ctx.options.severity,
        confidence: 0.9,
        ts: ev.ts,
        actual: `${win.dstCount} hosts/window`,
        expected: `<= ${limit}`,
        data: { hosts: win.dstCount, limit },
        attack: ['T1046'],
      };
    }
  },

  /**
   * @param {{ stats: { count: number, mean: number, m2: number, max: number }, cachedLimit: number | null }} dev
   * @param {{ dstCount: number }} win
   * @param {{ learning: boolean }} ctx
   */
  onWindowClose(dev, win, ctx) {
    if (!ctx.learning) return;
    pushSample(dev.stats, win.dstCount);
    dev.cachedLimit = null;
  },

  /** @param {{ stats: { count: number, mean: number, m2: number, max: number } }} dev */
  exportState(dev) {
    return {
      count: dev.stats.count,
      mean: dev.stats.mean,
      m2: dev.stats.m2,
      max: dev.stats.max,
    };
  },

  /**
   * @param {{ stats: any, cachedLimit: number | null }} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    dev.stats = readStreamState(state, caps.maxWindows, 'fan-out');
    dev.cachedLimit = null;
  },

  memoryEstimate() {
    return 64;
  },
};

module.exports = detector;
