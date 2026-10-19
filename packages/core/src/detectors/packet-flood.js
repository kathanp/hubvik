'use strict';

const { explainThreshold } = require('./lib');

const detector = {
  id: 'packet-flood',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: 'Very low',
    attack: ['T1498'],
    explains: true,
    stage: 'impact',
    dedupGroup: 'flood',
  },
  requires: ['T1'],
  category: 'volume',
  hardRule: true,
  defaults: { minPackets: 500, maxBytesPerPacket: 100, severity: 'critical' },

  createState() {
    return { win: null, pkts: 0, bytes: 0, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow') return;
    if (dev.win !== ctx.window.start) {
      dev.win = ctx.window.start;
      dev.pkts = 0;
      dev.bytes = 0;
      dev.fired = false;
    }
    const pkts = (ev.pktsOut || 0) + (ev.pktsIn || 0);
    const bytes = (ev.bytesOut || 0) + (ev.bytesIn || 0);
    dev.pkts += pkts;
    dev.bytes += bytes;
    if (dev.fired || dev.pkts < ctx.options.minPackets) return;
    const avg = dev.bytes / dev.pkts;
    if (avg >= ctx.options.maxBytesPerPacket) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${dev.pkts} packets, ${Math.round(avg)} bytes/packet`,
      expected: `< ${ctx.options.minPackets} packets or larger packets`,
      data: { packets: dev.pkts, bytesPerPacket: avg },
      explain: explainThreshold({
        test: 'gte',
        observed: dev.pkts,
        threshold: ctx.options.minPackets,
        formula: `minPackets=${ctx.options.minPackets}`,
      }),
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev */
  importState(dev) {
    dev.win = null;
    dev.pkts = 0;
    dev.bytes = 0;
    dev.fired = false;
  },

  memoryEstimate() {
    return 32;
  },
};

module.exports = detector;
