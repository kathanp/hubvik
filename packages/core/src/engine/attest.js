'use strict';

const { createHash, createHmac, timingSafeEqual } = require('node:crypto');
const { HubvikError } = require('../errors');
const { canonical } = require('./baseline');
const { assertSafeKeys } = require('./validate');
const { version } = require('../../package.json');

const RATE_KEYS = new Set(['detectionRate', 'detection-rate', 'detection_rate']);

/**
 * @param {any} engine
 * @returns {object}
 */
function rawOpts(engine) {
  if (engine.opts && engine.opts.raw) return engine.opts.raw;
  const shard = engine.engines && engine.engines[0];
  return shard && shard.opts ? shard.opts.raw : {};
}

/**
 * @param {object} raw
 * @returns {string}
 */
function optionsHash(raw) {
  return createHash('sha256').update(canonical(raw)).digest('hex');
}

/**
 * @param {string | Buffer} key
 * @param {object} body
 */
function signBody(key, body) {
  const mac = createHmac('sha256', key).update(canonical(body)).digest('hex');
  return { ...body, sig: { alg: 'HMAC-SHA256', mac } };
}

/**
 * @param {unknown} key
 * @returns {void}
 */
function requireKey(key) {
  if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
    throw new HubvikError('ATTEST_KEY_IS_INVALID', 'attest key is invalid');
  }
}

/**
 * Copy the lines the caller already measured. This function does not time anything.
 * @param {unknown} bench
 * @returns {string[]}
 */
function copyBench(bench) {
  if (!Array.isArray(bench)) {
    throw new HubvikError('ATTEST_BENCH_IS_INVALID', 'attest bench is invalid');
  }
  /** @type {string[]} */
  const lines = [];
  for (const line of bench) {
    if (typeof line !== 'string') {
      throw new HubvikError('ATTEST_BENCH_IS_INVALID', 'attest bench is invalid');
    }
    lines.push(line);
  }
  return lines;
}

/**
 * @param {{ scenario: string, fired: string[], missing: string[] }[]} rows
 */
function scenarioRows(rows) {
  return rows.map((row) => ({
    scenario: row.scenario,
    status: row.missing.length === 0 ? 'fired' : 'blind',
    fired: row.fired.slice(),
  }));
}

/**
 * @param {any} engine
 * @param {any} opts
 */
function attestOf(engine, opts) {
  if (!opts || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new HubvikError('ATTEST_IS_INVALID', 'attest is invalid');
  }
  assertSafeKeys(opts, 'attest');
  requireKey(opts.key);
  const bench = copyBench(opts.bench);
  const summary = engine.coverage().summary;
  const body = {
    v: 1,
    engine: version,
    optionsHash: optionsHash(rawOpts(engine)),
    coverage: {
      live: summary.live,
      shadowOnly: summary.shadowOnly,
      blind: summary.blind,
    },
    scenarios: scenarioRows(engine.selftest()),
    bench,
  };
  return signBody(opts.key, body);
}

/**
 * @param {unknown} value
 * @param {Set<object>} seen
 * @returns {boolean}
 */
function hasRate(value, seen) {
  if (!value || typeof value !== 'object') return false;
  if (seen.has(value)) return false;
  seen.add(value);
  for (const key of Object.keys(value)) {
    if (RATE_KEYS.has(key)) return true;
    if (hasRate(/** @type {Record<string, unknown>} */ (value)[key], seen)) return true;
  }
  return false;
}

/**
 * @param {any} doc
 * @returns {boolean}
 */
function shapeOk(doc) {
  if (doc.v !== 1 || typeof doc.engine !== 'string' || doc.engine.length === 0) return false;
  if (typeof doc.optionsHash !== 'string' || !/^[0-9a-f]{64}$/.test(doc.optionsHash)) return false;
  const cov = doc.coverage;
  if (!cov || typeof cov !== 'object') return false;
  if (![cov.live, cov.shadowOnly, cov.blind].every((n) => Number.isInteger(n) && n >= 0)) {
    return false;
  }
  if (!Array.isArray(doc.scenarios) || !Array.isArray(doc.bench)) return false;
  for (const row of doc.scenarios) {
    if (!row || typeof row !== 'object') return false;
    if (row.status !== 'fired' && row.status !== 'blind') return false;
    if (typeof row.scenario !== 'string' || !Array.isArray(row.fired)) return false;
    if (row.fired.some((/** @type {unknown} */ id) => typeof id !== 'string')) return false;
  }
  return doc.bench.every((/** @type {unknown} */ line) => typeof line === 'string');
}

/**
 * Check the HMAC and the options hash. A detection-rate field fails the check.
 * @param {any} doc
 * @param {string | Buffer} key
 * @returns {boolean}
 */
function verifyAttestation(doc, key) {
  if (typeof key !== 'string' && !Buffer.isBuffer(key)) return false;
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return false;
  try {
    assertSafeKeys(doc, 'attestation');
  } catch {
    return false;
  }
  if (hasRate(doc, new Set())) return false;
  if (!shapeOk(doc)) return false;
  const mac = doc.sig && doc.sig.mac;
  if (
    !doc.sig ||
    doc.sig.alg !== 'HMAC-SHA256' ||
    typeof mac !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(mac)
  ) {
    return false;
  }
  const expected = Buffer.from(
    createHmac('sha256', key).update(canonical(doc)).digest('hex'),
    'hex',
  );
  const actual = Buffer.from(mac, 'hex');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

const attestMethods = {
  /**
   * Signed self-test document. The live engine is not fed.
   * `bench` is copied. This call does not measure it.
   * @this {any}
   * @param {{ key: string | Buffer, bench: string[] }} opts
   */
  attest(opts) {
    return attestOf(this, opts);
  },
};

module.exports = { attestMethods, verifyAttestation };
