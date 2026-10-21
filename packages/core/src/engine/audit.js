'use strict';

const { HubvikError } = require('../errors');

const { createHash, createHmac } = require('node:crypto');
const { assertSafeKeys } = require('./validate/common');

/** Ring capacity (G9, D-60). */
const CAP = 10_000;
const ZERO_HASH = '0'.repeat(64);
const MAX_DEPTH = 32;
const MAX_NODES = 100_000;
const MAX_ARG_STRING = 1_000_000;
const MAX_FIELD = 255;
const MAX_KEY = 4096;

const KINDS = new Set([
  'allow',
  'suppress',
  'ack',
  'lock',
  'relearn',
  'forget',
  'annotate',
  'removeAnnotation',
  'loadRules',
  'loadIndicators',
  'loadTemplates',
  'importBaseline',
  'restore',
  'applyDelta',
  'setDeviceClass',
  'setPeerGroup',
  'setDeviceCriticality',
  'promote',
  'feedback',
]);

const INPUT_KEYS = new Set(['ts', 'kind', 'operator', 'target', 'args']);
const RECORD_KEYS = new Set([
  'seq',
  'ts',
  'kind',
  'operator',
  'target',
  'argsDigest',
  'prevHash',
  'hash',
]);
const STATE_KEYS = new Set(['anchor', 'nextSeq', 'key', 'records']);

/**
 * @typedef {object} AuditRecord
 * @property {number} seq
 * @property {number} ts
 * @property {string} kind
 * @property {string | null} operator
 * @property {string | null} target
 * @property {string} argsDigest
 * @property {string} prevHash
 * @property {string} hash
 */

/**
 * @typedef {object} AuditLog
 * @property {AuditRecord[]} records Oldest record first.
 * @property {number} nextSeq
 * @property {string} anchor prevHash of the oldest record still in the ring.
 * @property {string | null} key HMAC key. Null selects plain SHA-256.
 */

/** @type {WeakSet<object>} */
const instances = new WeakSet();

/**
 * Empty tamper-evident ring. The anchor starts as 64 zero hex characters.
 * @returns {AuditLog}
 */
function createAuditLog() {
  const log = {
    records: /** @type {AuditRecord[]} */ ([]),
    nextSeq: 0,
    anchor: ZERO_HASH,
    key: /** @type {string | null} */ (null),
  };
  instances.add(log);
  return log;
}

/**
 * Append one operator action. `ts` is the caller's watermark.
 * `opts.key` selects HMAC-SHA256 for a log that does not yet have records.
 * @param {unknown} log
 * @param {unknown} recordInput
 * @param {unknown} [opts]
 * @returns {AuditRecord}
 */
function append(log, recordInput, opts) {
  const current = assertLog(log);
  const key = resolveKey(current, opts);
  const parsed = parseInput(recordInput);
  if (typeof current.anchor !== 'string') {
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  if (!Number.isSafeInteger(current.nextSeq) || current.nextSeq < 0) {
    throw new HubvikError('AUDIT_SEQ_IS_INVALID', 'audit seq is invalid');
  }
  if (current.nextSeq >= Number.MAX_SAFE_INTEGER) {
    throw new HubvikError('AUDIT_SEQ_IS_INVALID', 'audit seq is invalid');
  }
  const prevHash = previousHash(current);
  const argsDigest = digestHex(parsed.argsText, null).slice(0, 16);
  const record = {
    seq: current.nextSeq,
    ts: parsed.ts,
    kind: parsed.kind,
    operator: parsed.operator,
    target: parsed.target,
    argsDigest,
    prevHash,
    hash: '',
  };
  record.hash = chainHash(record, key);
  current.key = key;
  current.records.push(record);
  current.nextSeq += 1;
  if (current.records.length > CAP) {
    current.records.shift();
    const oldest = current.records[0];
    if (oldest) current.anchor = oldest.prevHash;
  }
  return copyRecord(record);
}

/**
 * Records in ring order. `sinceSeq` is inclusive.
 * @param {unknown} log
 * @param {unknown} [opts]
 * @returns {AuditRecord[]}
 */
function auditLog(log, opts) {
  const current = assertLog(log);
  const since = sinceOf(opts);
  /** @type {AuditRecord[]} */
  const out = [];
  for (const record of current.records) {
    if (typeof record.seq !== 'number' || !Number.isSafeInteger(record.seq)) {
      throw new HubvikError('AUDIT_SEQ_IS_INVALID', 'audit seq is invalid');
    }
    if (record.seq >= since) out.push(copyRecord(record));
  }
  return out;
}

/**
 * Recompute the chain. A broken link reports the sequence number where it failed.
 * @param {unknown} log
 * @returns {{ ok: true } | { ok: false, brokenAt: number }}
 */
function verifyAudit(log) {
  const current = assertLog(log);
  const records = current.records;
  if (!Array.isArray(records) || records.length > CAP) {
    return { ok: false, brokenAt: 0 };
  }
  if (!Number.isSafeInteger(current.nextSeq) || current.nextSeq < 0) {
    return { ok: false, brokenAt: 0 };
  }
  if (records.length === 0) {
    if (current.nextSeq === 0 && current.anchor === ZERO_HASH) return { ok: true };
    return { ok: false, brokenAt: 0 };
  }
  if (current.key != null && typeof current.key !== 'string') {
    return { ok: false, brokenAt: seqOf(records[0]) };
  }
  const key = typeof current.key === 'string' ? current.key : null;
  let expectedPrev = current.anchor;
  for (let i = 0; i < records.length; i += 1) {
    const record = records[i];
    const seq = seqOf(record);
    if (!record || typeof expectedPrev !== 'string' || record.prevHash !== expectedPrev) {
      return { ok: false, brokenAt: seq };
    }
    if (i > 0) {
      const previous = records[i - 1];
      if (!previous || record.seq !== previous.seq + 1) return { ok: false, brokenAt: seq };
    }
    let hash;
    try {
      hash = chainHash(record, key);
    } catch {
      return { ok: false, brokenAt: seq };
    }
    if (hash !== record.hash) return { ok: false, brokenAt: seq };
    expectedPrev = record.hash;
  }
  const first = records[0];
  if (!first || first.seq + records.length !== current.nextSeq) {
    const last = records[records.length - 1];
    return { ok: false, brokenAt: last && typeof last.seq === 'number' ? last.seq + 1 : 0 };
  }
  return { ok: true };
}

/**
 * Plain state. The caller can store it and pass it back to `fromJSON`.
 * @param {unknown} log
 * @returns {{ anchor: string, nextSeq: number, key: string | null, records: AuditRecord[] }}
 */
function toJSON(log) {
  const current = assertLog(log);
  return {
    anchor: current.anchor,
    nextSeq: current.nextSeq,
    key: current.key,
    records: current.records.map((record) => copyRecord(record)),
  };
}

/**
 * Validate `raw`, then replace `log`. A throw leaves `log` unchanged.
 * @param {unknown} log
 * @param {unknown} raw
 * @returns {AuditLog}
 */
function fromJSON(log, raw) {
  const current = assertLog(log);
  const next = parseState(raw);
  current.anchor = next.anchor;
  current.nextSeq = next.nextSeq;
  current.key = next.key;
  current.records = next.records;
  return current;
}

/**
 * @param {unknown} value
 * @returns {AuditLog}
 */
function assertLog(value) {
  if (value === null || typeof value !== 'object' || !instances.has(value)) {
    throw new HubvikError('AUDIT_LOG_IS_INVALID', 'audit log is invalid');
  }
  return /** @type {AuditLog} */ (value);
}

/**
 * @param {AuditLog} log
 * @param {unknown} opts
 * @returns {string | null}
 */
function resolveKey(log, opts) {
  if (opts == null) return log.key;
  if (typeof opts !== 'object' || Array.isArray(opts)) {
    throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
  }
  assertPlain(opts, 'audit.opts');
  const record = /** @type {Record<string, unknown>} */ (opts);
  if (Object.getOwnPropertySymbols(record).length > 0) {
    throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
  }
  for (const key of Object.keys(record)) {
    if (key !== 'key') throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
  }
  if (!Object.hasOwn(record, 'key') || record.key == null) return log.key;
  if (typeof record.key !== 'string' || record.key.length > MAX_KEY) {
    throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
  }
  if (log.key == null) {
    if (log.records.length !== 0)
      throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
    return record.key;
  }
  if (record.key !== log.key) throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
  return log.key;
}

/**
 * @param {unknown} raw
 * @returns {{ ts: number, kind: string, operator: string | null, target: string | null, argsText: string }}
 */
function parseInput(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  assertPlain(raw, 'audit.record');
  const record = /** @type {Record<string, unknown>} */ (raw);
  if (Object.getOwnPropertySymbols(record).length > 0) {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  for (const key of Object.keys(record)) {
    if (!INPUT_KEYS.has(key))
      throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  if (!Object.hasOwn(record, 'ts'))
    throw new HubvikError('AUDIT_TS_IS_INVALID', 'audit ts is invalid');
  const ts = record.ts;
  if (typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0) {
    throw new HubvikError('AUDIT_TS_IS_INVALID', 'audit ts is invalid');
  }
  if (typeof record.kind !== 'string' || !KINDS.has(record.kind)) {
    throw new HubvikError('AUDIT_KIND_IS_INVALID', 'audit kind is invalid');
  }
  const operator = optionalString(record, 'operator');
  const target = optionalString(record, 'target');
  const args = Object.hasOwn(record, 'args') ? record.args : null;
  return { ts, kind: record.kind, operator, target, argsText: canonicalJSON(args) };
}

/**
 * @param {Record<string, unknown>} record
 * @param {string} name
 * @returns {string | null}
 */
function optionalString(record, name) {
  if (!Object.hasOwn(record, name) || record[name] == null) return null;
  const value = record[name];
  if (typeof value !== 'string') {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  if (value.length > MAX_FIELD) throw new HubvikError('STRING_TOO_LONG', 'string too long');
  return value;
}

/**
 * @param {AuditLog} log
 * @returns {string}
 */
function previousHash(log) {
  if (log.records.length === 0) return log.anchor;
  const last = log.records[log.records.length - 1];
  if (!last || typeof last.hash !== 'string') {
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  return last.hash;
}

/**
 * @param {unknown} opts
 * @returns {number}
 */
function sinceOf(opts) {
  if (opts == null) return 0;
  if (typeof opts !== 'object' || Array.isArray(opts)) {
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  assertPlain(opts, 'audit');
  const record = /** @type {Record<string, unknown>} */ (opts);
  if (Object.getOwnPropertySymbols(record).length > 0) {
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  for (const key of Object.keys(record)) {
    if (key !== 'sinceSeq')
      throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  if (!Object.hasOwn(record, 'sinceSeq') || record.sinceSeq == null) return 0;
  if (
    typeof record.sinceSeq !== 'number' ||
    !Number.isSafeInteger(record.sinceSeq) ||
    record.sinceSeq < 0
  ) {
    throw new HubvikError('AUDIT_SEQ_IS_INVALID', 'audit seq is invalid');
  }
  return record.sinceSeq;
}

/**
 * @param {unknown} raw
 * @returns {{ anchor: string, nextSeq: number, key: string | null, records: AuditRecord[] }}
 */
function parseState(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  assertPlain(raw, 'audit');
  const body = /** @type {Record<string, unknown>} */ (raw);
  if (Object.getOwnPropertySymbols(body).length > 0) {
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  for (const key of Object.keys(body)) {
    if (!STATE_KEYS.has(key))
      throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  }
  const anchor = body.anchor;
  if (!isHex(anchor, 64)) throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  const nextSeq = body.nextSeq;
  if (typeof nextSeq !== 'number' || !Number.isSafeInteger(nextSeq) || nextSeq < 0) {
    throw new HubvikError('AUDIT_SEQ_IS_INVALID', 'audit seq is invalid');
  }
  /** @type {string | null} */
  let key = null;
  if (Object.hasOwn(body, 'key') && body.key != null) {
    if (typeof body.key !== 'string' || body.key.length > MAX_KEY) {
      throw new HubvikError('AUDIT_KEY_IS_INVALID', 'audit key is invalid');
    }
    key = body.key;
  }
  const items = body.records;
  if (!Array.isArray(items))
    throw new HubvikError('AUDIT_STATE_IS_INVALID', 'audit state is invalid');
  if (Object.getPrototypeOf(items) !== Array.prototype) {
    throw new HubvikError('FORBIDDEN_KEY_AT', 'forbidden key __proto__ at audit.records');
  }
  assertSafeKeys(items, 'audit.records');
  if (items.length > CAP) throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array records exceeds cap');
  /** @type {AuditRecord[]} */
  const records = [];
  for (const item of items) records.push(parseRecord(item));
  return { anchor, nextSeq, key, records };
}

/**
 * @param {unknown} raw
 * @returns {AuditRecord}
 */
function parseRecord(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  assertPlain(raw, 'audit.record');
  const record = /** @type {Record<string, unknown>} */ (raw);
  if (Object.getOwnPropertySymbols(record).length > 0) {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  for (const key of Object.keys(record)) {
    if (!RECORD_KEYS.has(key)) {
      throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
    }
  }
  for (const key of RECORD_KEYS) {
    if (!Object.hasOwn(record, key)) {
      throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
    }
  }
  const seq = record.seq;
  if (typeof seq !== 'number' || !Number.isSafeInteger(seq) || seq < 0) {
    throw new HubvikError('AUDIT_SEQ_IS_INVALID', 'audit seq is invalid');
  }
  const ts = record.ts;
  if (typeof ts !== 'number' || !Number.isFinite(ts) || ts < 0) {
    throw new HubvikError('AUDIT_TS_IS_INVALID', 'audit ts is invalid');
  }
  if (typeof record.kind !== 'string' || !KINDS.has(record.kind)) {
    throw new HubvikError('AUDIT_KIND_IS_INVALID', 'audit kind is invalid');
  }
  if (!isHex(record.argsDigest, 16) || !isHex(record.prevHash, 64) || !isHex(record.hash, 64)) {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  return {
    seq,
    ts,
    kind: record.kind,
    operator: storedString(record.operator),
    target: storedString(record.target),
    argsDigest: record.argsDigest,
    prevHash: record.prevHash,
    hash: record.hash,
  };
}

/**
 * @param {unknown} value
 * @returns {string | null}
 */
function storedString(value) {
  if (value === null) return null;
  if (typeof value !== 'string') {
    throw new HubvikError('AUDIT_RECORD_IS_INVALID', 'audit record is invalid');
  }
  if (value.length > MAX_FIELD) throw new HubvikError('STRING_TOO_LONG', 'string too long');
  return value;
}

/**
 * @param {object} value
 * @param {string} path
 * @returns {void}
 */
function assertPlain(value, path) {
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new HubvikError('FORBIDDEN_KEY_AT', `forbidden key __proto__ at ${path}`);
  }
  assertSafeKeys(value, path);
}

/**
 * @param {unknown} value
 * @param {number} size
 * @returns {value is string}
 */
function isHex(value, size) {
  return typeof value === 'string' && value.length === size && /^[0-9a-f]+$/.test(value);
}

/**
 * @param {AuditRecord | undefined} record
 * @returns {number}
 */
function seqOf(record) {
  return record && typeof record.seq === 'number' ? record.seq : 0;
}

/**
 * @param {AuditRecord} record
 * @returns {AuditRecord}
 */
function copyRecord(record) {
  return {
    seq: record.seq,
    ts: record.ts,
    kind: record.kind,
    operator: record.operator,
    target: record.target,
    argsDigest: record.argsDigest,
    prevHash: record.prevHash,
    hash: record.hash,
  };
}

/**
 * SHA-256, or HMAC-SHA256 when `key` is a string.
 * The payload is `prevHash` concatenated with canonical JSON of the record without `hash`.
 * @param {AuditRecord} record
 * @param {string | null} key
 * @returns {string}
 */
function chainHash(record, key) {
  const body = {
    seq: record.seq,
    ts: record.ts,
    kind: record.kind,
    operator: record.operator,
    target: record.target,
    argsDigest: record.argsDigest,
    prevHash: record.prevHash,
  };
  return digestHex(`${record.prevHash}${canonicalJSON(body)}`, key);
}

/**
 * @param {string} payload
 * @param {string | null} key
 * @returns {string}
 */
function digestHex(payload, key) {
  if (key == null) return createHash('sha256').update(payload).digest('hex');
  return createHmac('sha256', key).update(payload).digest('hex');
}

/**
 * Canonical JSON. Object keys are sorted. Undefined object fields are omitted.
 * @param {unknown} value
 * @returns {string}
 */
function canonicalJSON(value) {
  const text = canonical(value, 0, new WeakSet());
  if (text === undefined) return 'null';
  return text;
}

/**
 * @param {unknown} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {string | undefined}
 */
function canonical(value, depth, seen) {
  if (value === undefined) return undefined;
  if (depth > MAX_DEPTH) throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  if (value === null) return 'null';
  if (typeof value === 'string') {
    if (value.length > MAX_ARG_STRING) {
      throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value))
      throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
    return JSON.stringify(value);
  }
  if (typeof value !== 'object')
    throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  if (seen.has(value)) throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  seen.add(value);
  try {
    if (Array.isArray(value)) return canonicalArray(value, depth, seen);
    return canonicalObject(value, depth, seen);
  } finally {
    seen.delete(value);
  }
}

/**
 * @param {unknown[]} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {string}
 */
function canonicalArray(value, depth, seen) {
  if (value.length > MAX_NODES)
    throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    throw new HubvikError('FORBIDDEN_KEY_AT', 'forbidden key __proto__ at audit.args');
  }
  assertSafeKeys(value, 'audit.args');
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  }
  /** @type {string[]} */
  const parts = [];
  for (const item of value) {
    const part = canonical(item, depth + 1, seen);
    parts.push(part === undefined ? 'null' : part);
  }
  return `[${parts.join(',')}]`;
}

/**
 * @param {object} value
 * @param {number} depth
 * @param {WeakSet<object>} seen
 * @returns {string}
 */
function canonicalObject(value, depth, seen) {
  assertPlain(value, 'audit.args');
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  }
  const record = /** @type {Record<string, unknown>} */ (value);
  const keys = Object.keys(record);
  if (keys.length > MAX_NODES)
    throw new HubvikError('AUDIT_ARGS_ARE_INVALID', 'audit args are invalid');
  keys.sort();
  /** @type {string[]} */
  const parts = [];
  for (const key of keys) {
    const part = canonical(record[key], depth + 1, seen);
    if (part === undefined) continue;
    parts.push(`${JSON.stringify(key)}:${part}`);
  }
  return `{${parts.join(',')}}`;
}

module.exports = {
  createAuditLog,
  append,
  auditLog,
  verifyAudit,
  toJSON,
  fromJSON,
};
