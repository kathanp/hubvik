'use strict';

const { HubvikError } = require('../errors');

const { LruSet } = require('../engine/caps');
const { assertSafeKeys } = require('../engine/validate');

const detector = {
  id: 'wrong-time',
  version: 1,
  meta: {
    consumes: [
      'summary',
      'flow',
      'dns',
      'tls',
      'http',
      'arp',
      'dhcp',
      'ra',
      'discovery',
      'mapping',
      'app',
    ],
    rel: '0.1',
    fpRisk: 'Medium',
  },
  requires: ['T0'],
  category: 'timing',
  defaults: { severity: 'low' },

  /** @param {any} caps */
  createState(caps) {
    return { hours: new Set(), seen: new LruSet(caps.maxAlertKeys) };
  },

  /**
   * @param {{ hours: Set<number> }} dev
   * @param {{ ts: number }} ev
   * @param {{ hour: (ts: number) => number }} ctx
   */
  learn(dev, ev, ctx) {
    const hour = ctx.hour(ev.ts);
    if (dev.hours.size < 64) dev.hours.add(hour);
  },

  /**
   * @param {{ hours: Set<number>, seen: any }} dev
   * @param {{ ts: number }} ev
   * @param {{ hour: (ts: number) => number, day: (ts: number) => number, options: { severity: string } }} ctx
   */
  check(dev, ev, ctx) {
    const hour = ctx.hour(ev.ts);
    if (dev.hours.has(hour)) return;
    const key = `${ctx.day(ev.ts)}:${hour}`;
    if (dev.seen.has(key)) return;
    dev.seen.add(key);
    const known = [...dev.hours].sort((a, b) => a - b);
    return {
      severity: ctx.options.severity,
      confidence: 0.6,
      ts: ev.ts,
      actual: `active at hour ${hour}`,
      expected: `hours ${known.join(',')}`,
      data: { hour, knownHours: known },
    };
  },

  /** @param {{ hours: Set<number>, seen: any }} dev */
  exportState(dev) {
    return {
      hours: [...dev.hours].sort((a, b) => a - b),
      seen: dev.seen.toArray(),
    };
  },

  /**
   * @param {{ hours: Set<number>, seen: any }} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    const next = read(state, caps);
    dev.hours = next.hours;
    dev.seen = next.seen;
  },

  /** @param {{ hours: Set<number>, seen: any }} dev */
  memoryEstimate(dev) {
    return dev.hours.size * 8 + dev.seen.size * 32 + 32;
  },
};

/**
 * @param {any} state
 * @param {{ maxAlertKeys: number, maxString: number }} caps
 */
function read(state, caps) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new HubvikError('WRONG_TIME_STATE_IS_INVALID', 'wrong-time state is invalid');
  }
  assertSafeKeys(state, 'wrong-time');
  if (!Array.isArray(state.hours))
    throw new HubvikError('HOURS_MUST_BE_AN_ARRAY', 'hours must be an array');
  if (state.hours.length > 64)
    throw new HubvikError('ARRAY_HOURS_EXCEEDS_CAP', 'array hours exceeds cap');
  const hours = new Set();
  for (const hour of state.hours) {
    if (typeof hour !== 'number' || !Number.isFinite(hour))
      throw new HubvikError('HOURS_MUST_BE_NUMBERS', 'hours must be numbers');
    hours.add(hour);
  }
  const seen = new LruSet(caps.maxAlertKeys);
  const keys = state.seen ?? [];
  if (!Array.isArray(keys)) throw new HubvikError('SEEN_MUST_BE_AN_ARRAY', 'seen must be an array');
  if (keys.length > caps.maxAlertKeys)
    throw new HubvikError('ARRAY_SEEN_EXCEEDS_CAP', 'array seen exceeds cap');
  for (const key of keys) {
    if (typeof key !== 'string')
      throw new HubvikError('SEEN_MUST_BE_STRINGS', 'seen must be strings');
    if (key.length > caps.maxString) throw new HubvikError('STRING_TOO_LONG', 'string too long');
    seen.add(key);
  }
  return { hours, seen };
}

module.exports = detector;
