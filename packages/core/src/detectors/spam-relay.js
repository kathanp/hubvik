'use strict';

const detector = {
  id: 'spam-relay',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.2',
    fpRisk: '',
    attack: ['T1071'],
  },
  requires: ['T1'],
  category: 'abuse',
  hardRule: true,
  defaults: { minConnections: 10, severity: 'high' },

  createState() {
    return { hour: null, count: 0, fired: false, learned: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out' || ev.dstPort !== 25) return;
    const hour = Math.floor(ev.ts / 3600e3);
    if (dev.hour !== hour) {
      dev.hour = hour;
      dev.count = 0;
      dev.fired = false;
    }
    dev.count += 1;
    if (ctx.learning) dev.learned = true;
    if (dev.fired) return;
    const burst = dev.count > ctx.options.minConnections;
    if (!burst && (ctx.learning || dev.learned)) return;
    dev.fired = true;
    return draft(ctx, ev, dev.count);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { learned: dev.learned === true };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    dev.learned = Boolean(state && state.learned);
    dev.hour = null;
    dev.count = 0;
    dev.fired = false;
  },

  memoryEstimate() {
    return 24;
  },
};

/** @param {any} ctx @param {any} ev @param {number} count */
function draft(ctx, ev, count) {
  return {
    severity: ctx.options.severity,
    confidence: 0.88,
    ts: ev.ts,
    actual: `${count} SMTP connections this hour`,
    expected: `devices that do not relay mail`,
    data: { dstIp: ev.dstIp || null, count },
  };
}

module.exports = detector;
