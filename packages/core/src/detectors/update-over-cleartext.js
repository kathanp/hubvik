'use strict';

const { assertState } = require('./state');
const { explainThreshold } = require('./lib');

const PORTS = new Set([80, 21, 69]);

const detector = {
  id: 'update-over-cleartext',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
    explains: true,
  },
  requires: ['T1'],
  category: 'supply',
  defaults: { minBytes: 1000000, severity: 'medium' },

  createState() {
    return { fired: false };
  },

  /** @param {any} ev */
  prepare(ev) {
    return (
      ev.type === 'flow' &&
      ev.direction === 'in' &&
      (PORTS.has(ev.dstPort) || PORTS.has(ev.srcPort))
    );
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || ev.type !== 'flow' || ev.direction !== 'in') return;
    if (!PORTS.has(ev.dstPort) && !PORTS.has(ev.srcPort)) return;
    if ((ev.bytesIn || 0) < ctx.options.minBytes) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: `${ev.bytesIn} bytes on port ${ev.dstPort}`,
      expected: 'large downloads over TLS',
      data: { bytesIn: ev.bytesIn, port: ev.dstPort },
      explain: explainThreshold({
        test: 'gte',
        observed: ev.bytesIn || 0,
        threshold: ctx.options.minBytes,
        formula: `minBytes=${ctx.options.minBytes}`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = Boolean(state && state.fired);
  },

  memoryEstimate() {
    return 8;
  },
};

module.exports = detector;
