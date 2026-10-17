'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'stream-to-new-destination',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'app',
  defaults: { minMediaBytes: 1000000, severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const dst = mediaDst(ev);
    if (dst) dev.seen.add(dst);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'out') return;
    if (flooded(ctx, ev.dstIp)) return;
    const dst = ev.dstName || ev.dstIp;
    const media = ev.dstPort === 554 || (ev.bytesOut || 0) >= ctx.options.minMediaBytes;
    if (!media || !dst || dev.seen.has(dst) || dev.fired.has(dst)) return;
    dev.fired.add(dst);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: dst,
      expected: 'media only to a learned host',
      data: { dst, port: ev.dstPort, bytesOut: ev.bytesOut },
    };
  },

  exportState: exportSeen,

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },

  memoryEstimate: memorySeen,
};

/**
 * @param {any} ev
 */
function mediaDst(ev) {
  if (ev.type !== 'flow') return null;
  if (ev.dstPort === 554 || (ev.bytesOut || 0) >= 1000000) return ev.dstName || ev.dstIp;
  return null;
}

/**
 * True when egress-flood already fired for this address in the current window.
 * @param {any} ctx
 * @param {string | undefined} dstIp
 * @returns {boolean}
 */
function flooded(ctx, dstIp) {
  const marked = ctx.window && ctx.window.egressDsts;
  return Boolean(marked && dstIp && marked.has(dstIp));
}

module.exports = detector;
