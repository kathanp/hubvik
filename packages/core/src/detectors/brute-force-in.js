'use strict';

const { assertState } = require('./state');

const PORTS = new Set([22, 23, 3389, 554, 1883, 8080]);

const detector = {
  id: 'brute-force-in',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Low',
    attack: ['T1110'],
  },
  requires: ['T1'],
  category: 'scan',
  defaults: { minHits: 15, severity: 'high' },

  createState() {
    return { win: null, count: 0, fired: false, src: null };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (
      ev.type !== 'flow' ||
      ev.direction !== 'in' ||
      ev.proto !== 'tcp' ||
      !PORTS.has(ev.dstPort)
    ) {
      return;
    }
    const bytes = (ev.bytesOut || 0) + (ev.bytesIn || 0);
    if (ev.durationMs > 2000 || bytes > 2000) return;
    if (dev.win !== ctx.window.start) {
      dev.win = ctx.window.start;
      dev.count = 0;
      dev.fired = false;
    }
    dev.count += 1;
    dev.src = ev.srcIp;
    if (dev.fired || dev.count <= ctx.options.minHits) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${dev.src} sent ${dev.count} auth attempts`,
      expected: `<= ${ctx.options.minHits} per window`,
      data: { srcIp: dev.src, count: dev.count },
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
    dev.src = null;
  },

  memoryEstimate() {
    return 24;
  },
};

module.exports = detector;
