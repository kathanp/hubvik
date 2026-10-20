'use strict';

const { assertState } = require('./state');

const WRITE = /write|fc5|fc6|fc15|fc16/i;

const detector = {
  id: 'ot-schedule-drift',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Medium', consumes: ['app'] },
  requires: ['T5'],
  category: 'ot',
  defaults: { enabled: true, severity: 'medium' },

  createState() {
    return { pairs: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    const slot = pair(dev, ev, ctx);
    if (!slot) return;
    slot.hours.add(hourOfWeek(ev.ts));
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const slot = pair(dev, ev, ctx);
    if (!slot || slot.hours.size < 4) return;
    const hour = hourOfWeek(ev.ts);
    if (slot.hours.has(hour)) return;
    const key = `${ev.peerIp}|${ev.op}|${hour}`;
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: ev.ts,
      actual: `${ev.op} at hour-of-week ${hour}`,
      expected: 'a write inside the learned hours',
      data: { op: ev.op, hour, learned: slot.hours.size },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      pairs: [...dev.pairs.entries()].map(([key, slot]) => ({ key, hours: [...slot.hours] })),
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.pairs = new Map();
    dev.fired = new Set();
    const rows = Array.isArray(state.pairs) ? state.pairs.slice(0, 32) : [];
    for (const row of rows) {
      if (!row || typeof row.key !== 'string' || !Array.isArray(row.hours)) continue;
      dev.pairs.set(row.key, { hours: new Set(row.hours.slice(0, 168)) });
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.pairs.size * 64 + 16;
  },
};

/**
 * @param {number} ts
 */
function hourOfWeek(ts) {
  const date = new Date(ts);
  return date.getUTCDay() * 24 + date.getUTCHours();
}

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function pair(dev, ev, ctx) {
  if (ev.type !== 'app' || !WRITE.test(String(ev.op || ''))) return null;
  const key = `${ev.peerIp}|${ev.op}`;
  let slot = dev.pairs.get(key);
  if (!slot) {
    if (dev.pairs.size >= 32) return null;
    slot = { hours: new Set() };
    dev.pairs.set(key, slot);
  }
  if (ctx && ctx.learning) slot.hours.add(hourOfWeek(ev.ts));
  return slot;
}

module.exports = detector;
