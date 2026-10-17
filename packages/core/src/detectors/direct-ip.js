'use strict';

const { isPublic } = require('../engine/net');
const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'direct-ip',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Low on IoT; hard-coded C2 IPs are classic',
    attack: ['T1071'],
    stage: 'c2',
  },
  requires: ['T1', 'T2'],
  category: 'destination',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    remember(dev, ev);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type === 'dns') {
      remember(dev, ev);
      return;
    }
    if (ev.type !== 'flow' || ev.direction !== 'out') return;
    if (ev.dstName) {
      remember(dev, ev);
      return;
    }
    if (!isPublic(ev.dstIp) || dev.seen.has(ev.dstIp) || dev.fired.has(ev.dstIp)) return;
    dev.fired.add(ev.dstIp);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: ev.dstIp,
      expected: 'an address this device resolved',
      data: { dstIp: ev.dstIp },
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
 * @param {any} dev
 * @param {any} ev
 */
function remember(dev, ev) {
  if (ev.type === 'dns' && Array.isArray(ev.answers)) {
    for (const answer of ev.answers) {
      if (answer && typeof answer.value === 'string' && isPublic(answer.value))
        dev.seen.add(answer.value);
    }
  }
  if (ev.type === 'flow' && ev.dstName && isPublic(ev.dstIp)) dev.seen.add(ev.dstIp);
}

module.exports = detector;
