'use strict';

const { HubvikError } = require('../errors');

const { assertState, readStrings } = require('./state');
const { explainMatch } = require('./lib');

const CAP = 64;
const DAY = 86400000;

const detector = {
  id: 'onion-name',
  version: 1,
  meta: {
    rel: '2.0',
    mode: 'shadow',
    fpRisk: 'Low. An IoT device does not look up a Tor hidden service',
    consumes: ['dns', 'tls', 'flow'],
    explains: true,
    attack: ['T1090.003'],
    stage: 'c2',
  },
  requires: ['T2'],
  category: 'destination',
  hardRule: false,
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return { learned: new Set(), seen: new Map() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const name = onionName(ev);
    if (!name || dev.learned.has(name) || dev.learned.size >= CAP) return;
    dev.learned.add(name);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const name = onionName(ev);
    if (!name || dev.learned.has(name)) return;
    const prev = dev.seen.get(name);
    if (prev != null && ev.ts - prev < DAY) return;
    if (prev == null && dev.seen.size >= CAP) return;
    dev.seen.set(name, ev.ts);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: name,
      expected: 'no .onion name',
      explain: explainMatch({ observed: name, matched: '.onion', source: 'qname' }),
      data: { name },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    /** @type {{ name: string, ts: number }[]} */
    const seen = [];
    for (const [name, ts] of dev.seen) seen.push({ name, ts });
    return { learned: [...dev.learned], seen };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.learned = new Set(readStrings(state.learned, CAP, caps.maxString, 'learned'));
    dev.seen = new Map();
    if (state.seen == null) return;
    if (!Array.isArray(state.seen))
      throw new HubvikError('MUST_BE_AN_ARRAY', 'seen must be an array');
    if (state.seen.length > CAP)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array seen exceeds cap');
    for (const row of state.seen) {
      if (!row || typeof row !== 'object' || Array.isArray(row))
        throw new HubvikError('STATE_IS_INVALID', 'onion-name row is invalid');
      assertState(row, detector.id);
      if (typeof row.name !== 'string' || typeof row.ts !== 'number')
        throw new HubvikError('STATE_IS_INVALID', 'onion-name row is invalid');
      if (row.name.length > caps.maxString)
        throw new HubvikError('STRING_TOO_LONG', 'string too long');
      dev.seen.set(row.name, row.ts);
    }
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    return 64 + (dev.learned.size + dev.seen.size) * 48;
  },
};

/**
 * DNS name, SNI, or flow name that is a Tor hidden-service name.
 * `tor-or-proxy` stays quiet unless an indicator feed is loaded.
 * @param {any} ev
 * @returns {string | null}
 */
function onionName(ev) {
  if (!ev) return null;
  const raw =
    ev.type === 'dns'
      ? ev.qname
      : ev.type === 'tls'
        ? ev.sni
        : ev.type === 'flow'
          ? ev.dstName
          : null;
  if (typeof raw !== 'string') return null;
  const name = raw.toLowerCase().replace(/\.$/, '');
  if (name.length < 7 || !name.endsWith('.onion')) return null;
  return name;
}

module.exports = detector;
