'use strict';

const { HubvikError } = require('../errors');

const { explainThreshold } = require('./lib');

const CAP = 256;
const PORTS = new Set([22, 23, 2323]);
const SHORT = 3000;
const LONG = 60000;
const WINDOW = 30 * 60 * 1000;

const detector = {
  id: 'ssh-brute-then-session',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Very low',
    consumes: ['flow'],
    explains: true,
  },
  requires: ['T1'],
  category: 'credential',
  hardRule: false,
  defaults: { enabled: true, severity: 'critical', minShort: 10 },

  createState() {
    return { sources: new Map() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (!ev || ev.type !== 'flow' || ev.direction !== 'in' || ev.proto !== 'tcp') return;
    if (!PORTS.has(ev.dstPort) || typeof ev.srcIp !== 'string') return;
    const row = touch(dev.sources, ev.srcIp);
    if (row.fired) return;
    const duration = ev.durationMs || 0;
    if (duration <= SHORT) {
      if (row.shorts === 0) row.firstShort = ev.ts;
      row.shorts += 1;
      row.lastShort = ev.ts;
      return;
    }
    if (duration < LONG || row.shorts < ctx.options.minShort) return;
    if (row.lastShort == null || ev.ts - row.lastShort > WINDOW) return;
    row.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.srcIp} ${row.shorts} short then ${duration} ms`,
      expected: 'no long session after a brute force',
      explain: explainThreshold({
        test: 'gte',
        observed: row.shorts,
        threshold: ctx.options.minShort,
        formula: 'short sessions then one long session',
      }),
      data: { srcIp: ev.srcIp, shorts: row.shorts, durationMs: duration },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { sources: [...dev.sources.entries()] };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.sources = new Map();
    if (!state || !Array.isArray(state.sources)) return;
    if (state.sources.length > CAP)
      throw new HubvikError('ARRAY_SOURCES_EXCEEDS_CAP', 'array sources exceeds cap');
    for (const pair of state.sources) {
      if (!Array.isArray(pair) || pair.length !== 2 || !pair[1]) continue;
      dev.sources.set(String(pair[0]), {
        shorts: pair[1].shorts || 0,
        firstShort: pair[1].firstShort ?? null,
        lastShort: pair[1].lastShort ?? null,
        fired: Boolean(pair[1].fired),
      });
    }
  },
};

/**
 * @param {Map<string, any>} map
 * @param {string} key
 */
function touch(map, key) {
  const existing = map.get(key);
  if (existing) {
    map.delete(key);
    map.set(key, existing);
    return existing;
  }
  while (map.size >= CAP) {
    const oldest = map.keys().next().value;
    if (oldest == null) break;
    map.delete(oldest);
  }
  const row = { shorts: 0, firstShort: null, lastShort: null, fired: false };
  map.set(key, row);
  return row;
}

module.exports = detector;
