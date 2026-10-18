'use strict';

const { isMulticast, isLinkLocal } = require('../engine/net');
const { assertState } = require('./state');
const { assertSafeKeys } = require('../engine/validate');

const BUCKETS = new Set([64, 128, 255]);

const detector = {
  id: 'ttl-anomaly',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['flow'],
  },
  requires: ['T1'],
  category: 'spoof',
  hardRule: false,
  defaults: { enabled: true, severity: 'medium', minSamples: 20 },

  createState() {
    return { buckets: new Set(), samples: 0, alerted: new Set() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    const bucket = usableBucket(ev);
    if (bucket == null) return;
    dev.buckets.add(bucket);
    dev.samples += 1;
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const bucket = usableBucket(ev);
    if (bucket == null) return;
    const minSamples = ctx.options.minSamples;
    if (dev.samples < minSamples) return;
    if (dev.buckets.has(bucket) || dev.alerted.has(bucket)) return;
    dev.alerted.add(bucket);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `ttl bucket ${bucket}`,
      expected: `learned buckets ${[...dev.buckets].sort((a, b) => a - b).join(',')}`,
      dedupKey: String(bucket),
      data: {
        bucket,
        observedTtl: ev.ttl,
        learned: [...dev.buckets].sort((a, b) => a - b),
      },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      buckets: [...dev.buckets].sort((a, b) => a - b),
      samples: dev.samples,
      alerted: [...dev.alerted].sort((a, b) => a - b),
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    assertState(state, detector.id);
    const next = readState(state);
    dev.buckets = next.buckets;
    dev.samples = next.samples;
    dev.alerted = next.alerted;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return 32 + dev.buckets.size * 8 + dev.alerted.size * 8;
  },
};

/**
 * Outbound unicast TTL mapped to 64, 128, or 255. Under 16 and skipped destinations are ignored.
 * @param {any} ev
 * @returns {number | null}
 */
function usableBucket(ev) {
  if (ev.type !== 'flow' || ev.direction !== 'out') return null;
  if (typeof ev.dstIp === 'string' && skipDestination(ev.dstIp)) return null;
  return bucketOf(ev.ttl);
}

/**
 * @param {unknown} ttl
 * @returns {number | null}
 */
function bucketOf(ttl) {
  if (typeof ttl !== 'number' || !Number.isInteger(ttl) || ttl < 16 || ttl > 255) return null;
  if (ttl <= 64) return 64;
  if (ttl <= 128) return 128;
  return 255;
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function skipDestination(ip) {
  return ip === '255.255.255.255' || isMulticast(ip) || isLinkLocal(ip);
}

/**
 * @param {any} state
 */
function readState(state) {
  assertSafeKeys(state, detector.id);
  if (!Array.isArray(state.buckets)) throw new Error('buckets must be an array');
  if (state.buckets.length > 3) throw new Error('array buckets exceeds cap');
  if (!Array.isArray(state.alerted)) throw new Error('alerted must be an array');
  if (state.alerted.length > 3) throw new Error('array alerted exceeds cap');
  if (!Number.isInteger(state.samples) || state.samples < 0) {
    throw new Error('samples must be a non-negative integer');
  }
  const buckets = new Set();
  for (const value of state.buckets) {
    if (!BUCKETS.has(value)) throw new Error('bucket is invalid');
    buckets.add(value);
  }
  const alerted = new Set();
  for (const value of state.alerted) {
    if (!BUCKETS.has(value)) throw new Error('bucket is invalid');
    alerted.add(value);
  }
  return { buckets, samples: state.samples, alerted };
}

module.exports = detector;
