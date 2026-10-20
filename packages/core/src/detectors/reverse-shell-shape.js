'use strict';

const { assertState } = require('./state');

const HOUR = 3_600_000;

const detector = {
  id: 'reverse-shell-shape',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Medium', consumes: ['flow'] },
  requires: ['T1'],
  category: 'c2',
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return { known: new Set(), fired: new Map() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    if (ev.type === 'flow' && ev.dstIp && dev.known.size < 64) dev.known.add(ev.dstIp);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || dev.known.has(ev.dstIp)) return;
    const out = ev.pktsOut ? ev.bytesOut / ev.pktsOut : 0;
    const inn = ev.pktsIn ? ev.bytesIn / ev.pktsIn : 0;
    if (ev.pktsOut < 8 || ev.pktsIn < 8) return;
    if (out < 40 || out > 200 || inn < 40 || inn > 200) return;
    if (ev.durationMs < 30000) return;
    const prev = dev.fired.get(ev.dstIp);
    if (prev != null && ev.ts - prev < HOUR) return;
    if (dev.fired.size >= 64 && !dev.fired.has(ev.dstIp)) return;
    dev.fired.set(ev.dstIp, ev.ts);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `interactive session to ${ev.dstIp}`,
      expected: 'a destination seen while learning',
      data: { dstIp: ev.dstIp, bytesPerPacketOut: out, bytesPerPacketIn: inn },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { known: [...dev.known].slice(0, 64) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.known = new Set(Array.isArray(state.known) ? state.known.slice(0, 64).map(String) : []);
    dev.fired = new Map();
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.known.size * 20 + dev.fired.size * 16 + 16;
  },
};

module.exports = detector;
