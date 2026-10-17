'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'mqtt-wildcard-subscribe',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T5'],
  category: 'app',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || ev.proto !== 'mqtt' || ev.op !== 'SUBSCRIBE' || !ev.target) return;
    if (ev.target !== '#' && !ev.target.includes('/+') && !ev.target.startsWith('+')) return;
    if (dev.fired.has(ev.target)) return;
    dev.fired.add(ev.target);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: ev.target,
      expected: 'subscriptions to specific topics',
      data: { topic: ev.target },
    };
  },

  exportState: exportSeen,
  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },
  memoryEstimate: memorySeen,
};

module.exports = detector;
