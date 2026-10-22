'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'mud-violation',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Low', consumes: ['flow'] },
  requires: ['T1', 'T2'],
  category: 'policy',
  defaults: { enabled: true, severity: 'high' },

  /** @param {any} ev @param {any} ctx */
  prepare(ev, ctx) {
    return ev.type === 'flow' && typeof ctx.mud === 'function' && Boolean(ctx.mud());
  },

  createState() {
    return { fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const acl = typeof ctx.mud === 'function' ? ctx.mud() : null;
    if (!acl || !Array.isArray(acl.allows) || ev.type !== 'flow') return;
    const ok = acl.allows.some((/** @type {any} */ allow) => {
      if (allow.dstPort != null && allow.dstPort !== ev.dstPort) return false;
      if (allow.proto != null && allow.proto !== ev.proto) return false;
      if (allow.direction != null && allow.direction !== ev.direction) return false;
      if (allow.domain != null) {
        const name = String(ev.dstName || ev.dst || '');
        if (!name.endsWith(allow.domain)) return false;
      }
      return true;
    });
    if (ok) return;
    const key = `${ev.dstIp}:${ev.dstPort}`;
    if (dev.fired.has(key)) return;
    if (dev.fired.size >= 64) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.proto} ${ev.dstIp}:${ev.dstPort}`,
      expected: 'a destination allowed by the device MUD file',
      data: { dstIp: ev.dstIp, dstPort: ev.dstPort, proto: ev.proto },
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
