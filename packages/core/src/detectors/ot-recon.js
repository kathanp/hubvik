'use strict';

const { assertState } = require('./state');

const RECON = new Set(['Who-Is', 'Who-Has', 'fc43']);
const PORTS = new Set([47808, 502, 102, 44818, 20000, 1911, 4911]);

const detector = {
  id: 'ot-recon',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: '',
    stage: 'recon',
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { minTargets: 10, severity: 'high' },

  createState() {
    return { win: null, targets: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const target = reconTarget(ev);
    if (!target) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.targets = new Set();
      dev.fired = false;
    }
    if (dev.targets.size < 5000) dev.targets.add(target);
    if (dev.fired || dev.targets.size <= ctx.options.minTargets) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${dev.targets.size} OT targets`,
      expected: `<= ${ctx.options.minTargets} discovery targets per window`,
      data: { targets: dev.targets.size },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.targets = new Set();
    dev.fired = false;
  },

  memoryEstimate() {
    return 16;
  },
};

/**
 * @param {any} ev
 */
function reconTarget(ev) {
  if (ev.type === 'app' && RECON.has(ev.op)) return ev.peerIp || ev.target || ev.op;
  if (ev.type === 'flow' && PORTS.has(ev.dstPort)) return ev.dstIp;
  return null;
}

module.exports = detector;
