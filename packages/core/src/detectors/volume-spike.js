'use strict';

const { SampleRing } = require('../engine/caps');
const { summarize } = require('../engine/math');
const { readSamples } = require('./samples');

const detector = {
  id: 'volume-spike',
  version: 1,
  requires: ['T0'],
  category: 'volume',
  defaults: { sigma: 4, minBytes: 1_000_000, peakFactor: 2, severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { samples: new SampleRing(caps.maxWindows), cachedLimit: null };
  },

  learn() {},

  /**
   * @param {{ samples: any, cachedLimit: number | null }} dev
   * @param {{ bytes: number, start: number }} win
   * @param {{ learning: boolean, options: { sigma: number, minBytes: number, peakFactor: number, severity: string } }} ctx
   */
  onWindowClose(dev, win, ctx) {
    if (ctx.learning) {
      dev.samples.push(win.bytes);
      dev.cachedLimit = null;
      return;
    }
    if (win.bytes === 0) return;
    const limit = cachedLimit(dev, ctx.options);
    if (win.bytes > limit) {
      return {
        severity: ctx.options.severity,
        confidence: 0.85,
        ts: win.start,
        actual: `${win.bytes} bytes/window`,
        expected: `<= ${Math.round(limit)}`,
        data: { bytes: win.bytes, limit },
        attack: ['T1498'],
      };
    }
  },

  /** @param {{ samples: { toArray: () => number[], length: number } }} dev */
  exportState(dev) {
    return { samples: dev.samples.toArray() };
  },

  /**
   * @param {{ samples: any, cachedLimit: number | null }} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    dev.samples = readSamples(state, caps, 'volume-spike');
    dev.cachedLimit = null;
  },

  /** @param {{ samples: { length: number } }} dev */
  memoryEstimate(dev) {
    return dev.samples.length * 8 + 32;
  },
};

/**
 * @param {{ samples: any, cachedLimit: number | null }} dev
 * @param {{ sigma: number, minBytes: number, peakFactor: number }} options
 */
function cachedLimit(dev, options) {
  if (dev.cachedLimit == null) {
    const stats = summarize(dev.samples);
    dev.cachedLimit = Math.max(
      options.minBytes,
      stats.mean + options.sigma * stats.std,
      stats.max * options.peakFactor,
    );
  }
  return dev.cachedLimit;
}

module.exports = detector;
