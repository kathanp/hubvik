'use strict';

const { assertState } = require('./state');
const { explainThreshold } = require('./lib');

const detector = {
  id: 'protocol-mix-shift',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: 'Low',
    explains: true,
  },
  requires: ['T1'],
  category: 'volume',
  defaults: { minPackets: 20, band: 0.35, severity: 'high' },

  createState() {
    return { win: null, tcp: 0, other: 0, maxShare: 0, samples: 0 };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    tally(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    tally(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (dev.win !== win.start) return;
    const total = dev.tcp + dev.other;
    const share = total === 0 ? 0 : dev.other / total;
    dev.win = null;
    if (ctx.learning) {
      dev.maxShare = Math.max(dev.maxShare, share);
      dev.samples += 1;
      return;
    }
    if (dev.samples < 1 || total < ctx.options.minPackets) return;
    if (share < 0.5 || share <= dev.maxShare + ctx.options.band) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: win.start,
      actual: `${Math.round(share * 100)}% non-TCP`,
      expected: `near ${Math.round(dev.maxShare * 100)}% non-TCP`,
      data: { share, maxShare: dev.maxShare, total },
      explain: explainThreshold({
        test: 'gt',
        observed: share,
        threshold: dev.maxShare + ctx.options.band,
        formula: `maxShare=${dev.maxShare} + band=${ctx.options.band}`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { maxShare: dev.maxShare, samples: dev.samples };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.maxShare = typeof state.maxShare === 'number' ? state.maxShare : 0;
    dev.samples = typeof state.samples === 'number' ? state.samples : 0;
    dev.win = null;
    dev.tcp = 0;
    dev.other = 0;
  },

  memoryEstimate() {
    return 24;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 */
/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function tally(dev, ev, ctx) {
  if (ev.type !== 'flow') return;
  const pkts = (ev.pktsOut || 0) + (ev.pktsIn || 0);
  if (pkts <= 0) return;
  const start = ctx.window && ctx.window.start;
  if (start == null) return;
  if (dev.win !== start) {
    dev.win = start;
    dev.tcp = 0;
    dev.other = 0;
  }
  if (ev.proto === 'tcp') dev.tcp += pkts;
  else dev.other += pkts;
}

module.exports = detector;
