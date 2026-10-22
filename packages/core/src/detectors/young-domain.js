'use strict';

const { HubvikError } = require('../errors');

const { exactHit } = require('../engine/indicators');
const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');
const { assertSafeKeys } = require('../engine/validate');
const { explainMatch } = require('./lib');

const CAP = 1000;
const DAY = 86_400_000;

const detector = {
  id: 'young-domain',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: ['dns'],
    attack: ['T1583'],
    stage: 'c2',
    dedupGroup: 'indicator',
    explains: true,
  },
  requires: ['T2'],
  category: 'dns',
  hardRule: false,
  defaults: { enabled: true, severity: 'medium' },

  /**
   * @param {any} ev
   * @param {any} ctx
   */
  prepare(ev, ctx) {
    return (
      ev.type === 'dns' &&
      typeof ev.qname === 'string' &&
      Boolean(youngHit(ctx.indicatorIndex, ev.qname, ev.ts))
    );
  },

  createState() {
    return { families: new Map() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || typeof ev.qname !== 'string') return;
    const hit = youngHit(ctx.indicatorIndex, ev.qname, ev.ts);
    if (!hit) return;
    const family = domainFamily(ev.qname) || ev.qname.toLowerCase();
    if (!remember(dev.families, family, ev.ts)) return;
    return {
      severity: ctx.options.severity,
      confidence: typeof hit.confidence === 'number' ? hit.confidence : 0.8,
      ts: ev.ts,
      actual: ev.qname,
      expected: 'a name that is not on the young-domain list',
      dedupKey: family,
      data: { qname: ev.qname, family, value: hit.value, source: hit.source },
      explain: explainMatch({
        observed: ev.qname,
        matched: hit.value,
        source: hit.source || 'young-domain',
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      families: [...dev.families.entries()].map(([family, ts]) => ({ family, ts })),
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.families = readFamilies(state.families);
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.families.size * 64;
  },
};

/**
 * Domain-suffix match for indicator type `young-domain`. Expired rows are ignored.
 * @param {any} index
 * @param {string} name
 * @param {number} ts
 */
function youngHit(index, name, ts) {
  if (!index) return null;
  const labels = name.toLowerCase().split('.').filter(Boolean);
  for (let i = 0; i < labels.length - 1; i++) {
    const hit = exactHit(index, 'young-domain', labels.slice(i).join('.'), ts);
    if (hit) return hit;
  }
  return null;
}

/**
 * @param {Map<string, number>} families
 * @param {string} family
 * @param {number} ts
 * @returns {boolean}
 */
function remember(families, family, ts) {
  const prev = families.get(family);
  if (prev != null && ts - prev < DAY) return false;
  if (families.has(family)) families.delete(family);
  families.set(family, ts);
  if (families.size > CAP) {
    const oldest = families.keys().next().value;
    if (oldest !== undefined) families.delete(oldest);
  }
  return true;
}

/**
 * @param {unknown} value
 * @returns {Map<string, number>}
 */
function readFamilies(value) {
  if (!Array.isArray(value))
    throw new HubvikError('FAMILIES_MUST_BE_AN_ARRAY', 'families must be an array');
  if (value.length > CAP)
    throw new HubvikError('ARRAY_FAMILIES_EXCEEDS_CAP', 'array families exceeds cap');
  const families = new Map();
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new HubvikError('FAMILIES_MUST_BE_OBJECTS', 'families must be objects');
    }
    assertSafeKeys(item, 'young-domain.families');
    if (typeof item.family !== 'string' || item.family.length === 0 || item.family.length > 255) {
      throw new HubvikError('FAMILIES_MUST_BE_STRINGS', 'families must be strings');
    }
    if (!Number.isInteger(item.ts))
      throw new HubvikError('FAMILY_TIME_IS_INVALID', 'family time is invalid');
    families.set(item.family, item.ts);
  }
  if (families.size > CAP)
    throw new HubvikError('ARRAY_FAMILIES_EXCEEDS_CAP', 'array families exceeds cap');
  return families;
}

module.exports = detector;
