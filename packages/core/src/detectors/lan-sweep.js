'use strict';

const { isBogon } = require('../engine/net');
const { assertState } = require('./state');
const { isGroupDst } = require('./lib');

const detector = {
  id: 'lan-sweep',
  version: 1,
  meta: {
    consumes: ['flow', 'arp'],
    rel: '0.3',
    fpRisk: 'Low',
    attack: ['T1046'],
    stage: 'recon',
  },
  requires: ['T1'],
  category: 'scan',
  defaults: { minTargets: 20, severity: 'high' },

  createState() {
    return { win: null, targets: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const target = targetOf(ev);
    if (!target) return;
    if (dev.win !== ctx.window.start) {
      dev.win = ctx.window.start;
      dev.targets = new Set();
      dev.fired = false;
    }
    if (dev.targets.size < 5000) dev.targets.add(target);
    if (dev.fired || dev.targets.size <= ctx.options.minTargets) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${dev.targets.size} local targets`,
      expected: `<= ${ctx.options.minTargets} local targets per window`,
      data: { targets: dev.targets.size },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { win: dev.win };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.targets = new Set();
    dev.fired = false;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.targets.size * 16 + 16;
  },
};

/**
 * @param {any} ev
 * @returns {string | null}
 */
function targetOf(ev) {
  if (ev.type === 'arp' && ev.op === 'request') return ev.ip;
  if (isGroupDst(ev.dstIp)) return null;
  if (ev.type === 'flow' && ev.proto === 'icmp' && isBogon(ev.dstIp)) return ev.dstIp;
  return null;
}

module.exports = detector;
