'use strict';

const { explainThreshold, scratchBag } = require('./lib');

const MAC_CAP = 5000;

const detector = {
  id: 'wifi-deauth-flood',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['wifi'],
    explains: true,
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minCount: 30, perMac: 10 },

  createState() {
    return {};
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (!ev || (ev.op !== 'deauth' && ev.op !== 'disassoc')) return;
    const bag = shared(ctx);
    const start = ctx.window && typeof ctx.window.start === 'number' ? ctx.window.start : 0;
    if (bag.start !== start) {
      bag.start = start;
      bag.count = 0;
      bag.byMac = new Map();
      bag.fired = false;
    }
    if (bag.fired) return;
    bag.count += 1;
    const mac = ev.mac;
    const n = (bag.byMac.get(mac) || 0) + 1;
    if (bag.byMac.size < MAC_CAP || bag.byMac.has(mac)) bag.byMac.set(mac, n);
    if (bag.count >= ctx.options.minCount || n >= ctx.options.perMac) {
      bag.fired = true;
      const observed = n >= ctx.options.perMac ? n : bag.count;
      const threshold = n >= ctx.options.perMac ? ctx.options.perMac : ctx.options.minCount;
      return {
        severity: ctx.options.severity,
        confidence: 0.85,
        ts: ev.ts,
        actual: n >= ctx.options.perMac ? `${n} against ${mac}` : `${bag.count} deauth`,
        expected: `< ${ctx.options.minCount} per window and < ${ctx.options.perMac} per MAC`,
        explain: explainThreshold({
          test: 'gte',
          observed,
          threshold,
          formula: 'deauth + disassoc per window, or per target MAC',
        }),
        data: { count: bag.count, mac, macCount: n },
      };
    }
  },

  exportState() {
    return {};
  },

  importState() {},
};

/**
 * @param {any} ctx
 */
function shared(ctx) {
  return scratchBag(ctx, 'wifi-deauth-flood', () => ({
    start: null,
    count: 0,
    byMac: new Map(),
    fired: false,
  }));
}

module.exports = detector;
