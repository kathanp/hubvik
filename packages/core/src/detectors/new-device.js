'use strict';

const { explainNewMember } = require('./lib');

const detector = {
  id: 'new-device',
  version: 1,
  meta: {
    consumes: [
      'summary',
      'flow',
      'dns',
      'tls',
      'http',
      'arp',
      'dhcp',
      'ra',
      'discovery',
      'mapping',
      'app',
    ],
    rel: '0.2',
    fpRisk: 'Low',
    explains: true,
  },
  requires: ['T0'],
  category: 'link',
  hardRule: true,
  defaults: { severity: 'medium' },

  createState() {
    return { seen: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.seen) return;
    dev.seen = true;
    if (ctx.engineStarted == null || ev.ts - ctx.engineStarted <= ctx.learnMs) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: ev.device || ctx.deviceId,
      expected: 'devices seen before learning finished',
      data: { firstTs: ev.ts },
      explain: explainNewMember({
        observed: ev.device || ctx.deviceId,
        learnedCount: 0,
        sample: [],
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { seen: dev.seen };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    dev.seen = Boolean(state && state.seen);
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
