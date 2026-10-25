'use strict';

const { HubvikError } = require('../errors');

const { assertState, readStrings } = require('./state');
const { explainThreshold } = require('./lib');

const CAP = 64;
const DAY = 86400000;

const detector = {
  id: 'short-lived-cert',
  version: 1,
  meta: {
    rel: '1.6',
    mode: 'shadow',
    fpRisk: 'Medium. A device that renews a one-day certificate is learned',
    consumes: ['tls'],
    explains: true,
    attack: ['T1588.004'],
    stage: 'c2',
  },
  requires: ['T3'],
  category: 'tls',
  hardRule: false,
  defaults: { enabled: true, severity: 'medium', maxLifetimeMs: 172800000 },

  createState() {
    return { learned: new Set(), seen: new Map() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const name = nameOf(ev);
    if (!name || dev.learned.size >= CAP) return;
    dev.learned.add(name);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const life = lifetime(ev);
    if (!life) return;
    const name = nameOf(ev);
    if (!name || dev.learned.has(name)) return;
    if (!(life.span > 0) || life.span > ctx.options.maxLifetimeMs) return;
    const key = life.key;
    const prev = dev.seen.get(key);
    if (prev != null && ev.ts - prev < DAY) return;
    if (prev == null && dev.seen.size >= CAP) return;
    dev.seen.set(key, ev.ts);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${name} certificate lived ${life.span} ms`,
      expected: `longer than ${ctx.options.maxLifetimeMs} ms, or a learned name`,
      explain: explainThreshold({
        test: 'lt',
        observed: life.span,
        threshold: ctx.options.maxLifetimeMs + 1,
        formula: '0 < notAfter - notBefore <= maxLifetimeMs',
      }),
      data: { name, lifetimeMs: life.span, sha256: life.sha256 },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    /** @type {{ key: string, ts: number }[]} */
    const seen = [];
    for (const [key, ts] of dev.seen) seen.push({ key, ts });
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
      if (!row || typeof row.key !== 'string' || typeof row.ts !== 'number')
        throw new HubvikError('STATE_IS_INVALID', 'short-lived-cert row is invalid');
      if (row.key.length > caps.maxString)
        throw new HubvikError('STRING_TOO_LONG', 'string too long');
      dev.seen.set(row.key, row.ts);
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
 * @param {any} ev
 * @returns {string | null}
 */
function nameOf(ev) {
  if (!ev || ev.type !== 'tls') return null;
  if (typeof ev.sni === 'string' && ev.sni.length > 0) return ev.sni.toLowerCase();
  if (typeof ev.dstIp === 'string') return ev.dstIp;
  return null;
}

/**
 * @param {any} ev
 * @returns {{ span: number, key: string, sha256: string | null } | null}
 */
function lifetime(ev) {
  const cert = ev && ev.cert;
  if (!cert || typeof cert.notBefore !== 'number' || typeof cert.notAfter !== 'number') return null;
  const sha256 = typeof cert.sha256 === 'string' ? cert.sha256 : null;
  const key = sha256 || `${nameOf(ev)}|${cert.notBefore}|${cert.notAfter}`;
  return { span: cert.notAfter - cert.notBefore, key, sha256 };
}

module.exports = detector;
