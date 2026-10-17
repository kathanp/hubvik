'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'browser-mimic',
  version: 1,
  meta: {
    consumes: ['tls'],
    rel: '0.4',
    fpRisk: '',
    attack: ['T1036'],
  },
  requires: ['T3'],
  category: 'proxy',
  defaults: { severity: 'high' },

  createState() {
    return { fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || ev.type !== 'tls' || !ev.ja4) return;
    const browsers = ctx.browserJa4 || [];
    if (browsers.length === 0 || !browsers.includes(ev.ja4)) return;
    const classId = ctx.deviceClass && ctx.deviceClass.id;
    if (!classId || ctx.deviceClass.allowsBrowserJa4 === true) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: ev.ja4,
      expected: `${classId} does not speak with a browser fingerprint`,
      data: { ja4: ev.ja4, classId },
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
