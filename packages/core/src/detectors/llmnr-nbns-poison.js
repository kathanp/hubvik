'use strict';

const { assertState } = require('./state');

const PORTS = new Set([5355, 137]);

const detector = {
  id: 'llmnr-nbns-poison',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Low', consumes: ['dns'] },
  requires: ['T2'],
  category: 'identity',
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return { owned: new Set(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (!answer(ev) || dev.owned.size >= 256) return;
    dev.owned.add(ev.qname);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!answer(ev)) return;
    if (dev.owned.has(ev.qname) || dev.fired.has(ev.qname)) return;
    if (dev.fired.size >= 64) return;
    dev.fired.add(ev.qname);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${ev.qname} answered on port ${ev.port}`,
      expected: 'a name this device learned',
      data: { qname: ev.qname, port: ev.port },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { owned: [...dev.owned].slice(0, 256) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.owned = new Set(Array.isArray(state.owned) ? state.owned.slice(0, 256).map(String) : []);
    dev.fired = new Set();
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.owned.size * 24 + 16;
  },
};

/**
 * Optional dns.port must be 5355 or 137. Events without it stay quiet.
 * @param {any} ev
 */
function answer(ev) {
  return (
    ev &&
    ev.type === 'dns' &&
    PORTS.has(ev.port) &&
    ev.rcode === 'NOERROR' &&
    Array.isArray(ev.answers) &&
    ev.answers.length > 0 &&
    typeof ev.qname === 'string'
  );
}

module.exports = detector;
