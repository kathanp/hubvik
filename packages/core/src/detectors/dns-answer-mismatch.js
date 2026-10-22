'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'dns-answer-mismatch',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Low', consumes: ['dns'] },
  requires: ['T2'],
  category: 'dns',
  defaults: { enabled: true, severity: 'high' },

  /** @param {any} ev */
  prepare(ev) {
    return ev.type === 'dns' && typeof ev.from === 'string' && ev.from !== ev.resolver;
  },

  createState() {
    return { fired: new Set() };
  },

  /**
   * Quiet unless the event carries optional `from`, the address that sent the answer.
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || typeof ev.from !== 'string' || ev.from === ev.resolver) return;
    const key = `${ev.qname}|${ev.from}`;
    if (dev.fired.has(key) || dev.fired.size >= 64) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `answer for ${ev.qname} from ${ev.from}`,
      expected: `an answer from resolver ${ev.resolver}`,
      data: { qname: ev.qname, from: ev.from, resolver: ev.resolver },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: [...dev.fired].slice(0, 64) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = new Set(Array.isArray(state.fired) ? state.fired.slice(0, 64).map(String) : []);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.fired.size * 24 + 16;
  },
};

module.exports = detector;
