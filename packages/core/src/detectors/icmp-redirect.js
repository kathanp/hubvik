'use strict';

const { seenState, exportSeen, importSeen, memorySeen, explainMatch } = require('./lib');

const detector = {
  id: 'icmp-redirect',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
    explains: true,
  },
  requires: ['T1'],
  category: 'integrity',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} ev */
  prepare(ev) {
    return ev.type === 'flow' && ev.proto === 'icmp' && ev.icmpType === 5;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.proto !== 'icmp' || ev.icmpType !== 5) return;
    if (ctx.gatewayIp && ev.srcIp === ctx.gatewayIp) return;
    if (dev.fired.has(ev.srcIp)) return;
    dev.fired.add(ev.srcIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `redirect from ${ev.srcIp}`,
      expected: 'redirects only from the gateway',
      data: { srcIp: ev.srcIp },
      explain: explainMatch({
        observed: `redirect from ${ev.srcIp}`,
        matched: 5,
        source: 'icmpType',
      }),
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
