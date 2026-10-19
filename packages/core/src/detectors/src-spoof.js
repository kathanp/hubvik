'use strict';

const { assertState } = require('./state');
const { explainChanged } = require('./lib');

const detector = {
  id: 'src-spoof',
  version: 1,
  meta: {
    consumes: ['flow', 'dhcp'],
    rel: '0.3',
    fpRisk: '',
    explains: true,
  },
  requires: ['T1'],
  category: 'integrity',
  hardRule: true,
  defaults: { severity: 'critical' },

  createState() {
    return { lease: null, fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type === 'dhcp' && ev.msg === 'ack' && ev.requestedIp) {
      dev.lease = ev.requestedIp;
      return;
    }
    if (ev.type !== 'flow' || !dev.lease || dev.fired) return;
    if (ev.srcIp === dev.lease) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: ev.srcIp,
      expected: `source ${dev.lease}`,
      data: { srcIp: ev.srcIp, lease: dev.lease },
      explain: explainChanged({ observed: ev.srcIp, previous: dev.lease }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { lease: dev.lease };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.lease = state && typeof state.lease === 'string' ? state.lease : null;
    dev.fired = false;
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
