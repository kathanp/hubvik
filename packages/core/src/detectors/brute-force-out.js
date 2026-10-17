'use strict';

const { assertState } = require('./state');

const PORTS = new Set([22, 23, 3389, 554, 1883, 8080]);

const detector = {
  id: 'brute-force-out',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Very low',
    attack: ['T1110'],
    stage: 'spread',
  },
  requires: ['T1'],
  category: 'scan',
  hardRule: true,
  defaults: { minHits: 15, severity: 'critical' },

  createState() {
    return { win: null, count: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!authHit(ev, 'out')) return;
    if (dev.win !== ctx.window.start) {
      dev.win = ctx.window.start;
      dev.count = 0;
      dev.fired = false;
    }
    dev.count += 1;
    if (dev.fired || dev.count <= ctx.options.minHits) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${dev.count} short auth attempts`,
      expected: `<= ${ctx.options.minHits} per window`,
      data: { count: dev.count, port: ev.dstPort },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { count: dev.count };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.count = 0;
    dev.fired = false;
  },

  memoryEstimate() {
    return 16;
  },
};

/**
 * @param {any} ev
 * @param {'out' | 'in'} direction
 */
function authHit(ev, direction) {
  if (ev.type !== 'flow' || ev.direction !== direction || ev.proto !== 'tcp') return false;
  if (!PORTS.has(ev.dstPort)) return false;
  const bytes = (ev.bytesOut || 0) + (ev.bytesIn || 0);
  return ev.durationMs <= 2000 && bytes <= 2000;
}

module.exports = detector;
