'use strict';

const { SampleRing } = require('../engine/caps');
const { summarize } = require('../engine/math');
const { readSamples } = require('./samples');

const detector = {
  id: 'fan-out',
  version: 1,
  meta: {
    rel: '0.1',
    fpRisk: 'Low',
    attack: ['T1046'],
    stage: 'recon',
  },
  requires: ['T0'],
  category: 'scan',
  defaults: { minFanout: 10, fanoutFactor: 3, severity: 'high' },

  /**
   * @param {any} caps
   */
  createState(caps) {
    return { samples: new SampleRing(caps.maxWindows), cachedLimit: null };
  },

  learn() {},

  /**
   * @param {{ samples: any, cachedLimit: number | null }} dev
   * @param {{ ts: number }} ev
   * @param {{ options: { minFanout: number, fanoutFactor: number, severity: string }, window: { dstCount: number, fanoutAlerted: boolean } }} ctx
   */
  check(dev, ev, ctx) {
    const win = ctx.window;
    if (win.fanoutAlerted) return;
    if (dev.cachedLimit == null) {
      const stats = summarize(dev.samples);
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
   * @param {{ samples: any, cachedLimit: number | null }} dev
   * @param {{ dstCount: number }} win
   * @param {{ learning: boolean }} ctx
   */
  onWindowClose(dev, win, ctx) {
    if (!ctx.learning) return;
    dev.samples.push(win.dstCount);
    dev.cachedLimit = null;
  },

  /** @param {{ samples: any }} dev */
  exportState(dev) {
    return { samples: dev.samples.toArray() };
  },

  /**
   * @param {{ samples: any, cachedLimit: number | null }} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    dev.samples = readSamples(state, caps, 'fan-out');
    dev.cachedLimit = null;
  },

  /** @param {{ samples: any }} dev */
  memoryEstimate(dev) {
    return dev.samples.length * 8 + 32;
  },
};

module.exports = detector;
