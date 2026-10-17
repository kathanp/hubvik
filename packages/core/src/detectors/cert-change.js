'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'cert-change',
  version: 1,
  meta: {
    rel: '0.4',
    fpRisk: 'Low; strong MITM signal',
    attack: ['T1557'],
    stage: 'c2',
  },
  requires: ['T3'],
  category: 'tls',
  defaults: { severity: 'high' },

  createState() {
    return { issuers: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const issuer = issuerOf(ev);
    if (ev.sni && issuer) dev.issuers.set(ev.sni, issuer);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'tls' || !ev.sni) return;
    const issuer = issuerOf(ev);
    const previous = dev.issuers.get(ev.sni);
    if (!issuer || !previous || previous === issuer || dev.fired.has(ev.sni)) return;
    dev.fired.add(ev.sni);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.sni} issuer ${issuer}`,
      expected: `issuer ${previous}`,
      data: { sni: ev.sni, issuer, previous },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { issuers: [...dev.issuers.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.issuers = new Map();
    dev.fired = new Set();
    if (!Array.isArray(state.issuers)) return;
    if (state.issuers.length > 5000) throw new Error('array issuers exceeds cap');
    for (const pair of state.issuers) {
      if (!Array.isArray(pair) || pair.length !== 2) throw new Error('issuers must be pairs');
      dev.issuers.set(String(pair[0]), String(pair[1]));
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.issuers.size * 64 + 16;
  },
};

/**
 * @param {any} ev
 */
function issuerOf(ev) {
  return ev.cert && typeof ev.cert.issuer === 'string' ? ev.cert.issuer : null;
}

module.exports = detector;
