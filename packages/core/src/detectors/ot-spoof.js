'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'ot-spoof',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T5'],
  category: 'ot',
  defaults: { severity: 'critical' },

  createState() {
    return { owners: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const claim = iam(ev);
    if (claim && !dev.owners.has(claim.target)) dev.owners.set(claim.target, claim.peerIp);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const claim = iam(ev);
    if (!claim) return;
    const previous = dev.owners.get(claim.target);
    if (previous && previous !== claim.peerIp && !dev.fired.has(claim.target)) {
      dev.fired.add(claim.target);
      return {
        severity: ctx.options.severity,
        confidence: 0.9,
        ts: ev.ts,
        actual: `${claim.target} claimed by ${claim.peerIp}`,
        expected: `${claim.target} stays on ${previous}`,
        data: { target: claim.target, peerIp: claim.peerIp, previous },
      };
    }
    if (!previous) dev.owners.set(claim.target, claim.peerIp);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { owners: [...dev.owners.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.owners = new Map();
    dev.fired = new Set();
    if (!Array.isArray(state.owners) || state.owners.length > 5000) return;
    for (const pair of state.owners) {
      if (Array.isArray(pair) && pair.length === 2)
        dev.owners.set(String(pair[0]), String(pair[1]));
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.owners.size * 32 + 16;
  },
};

/**
 * @param {any} ev
 */
function iam(ev) {
  if (ev.type !== 'app' || ev.op !== 'I-Am' || !ev.target || !ev.peerIp) return null;
  return { target: ev.target, peerIp: ev.peerIp };
}

module.exports = detector;
