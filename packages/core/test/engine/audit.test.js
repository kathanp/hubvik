'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { mulberry32 } = require('../../../../test/fixtures/prng');
const { HubvikError } = require('../../src/errors');
const {
  createAuditLog,
  append,
  auditLog,
  verifyAudit,
  toJSON,
  fromJSON,
} = require('../../src/engine/audit');

const ZERO = '0'.repeat(64);
const KINDS = [
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
];

/**
 * @param {string} code
 * @returns {(err: unknown) => boolean}
 */
function codeIs(code) {
  return (err) => err instanceof HubvikError && err.code === code;
}

test('untampered short chain verifies', () => {
  const log = createAuditLog();
  append(log, {
    ts: 1_000,
    kind: 'allow',
    operator: 'alice',
    target: 'cam-1',
    args: { b: 1, a: 2 },
  });
  append(log, { ts: 2_000, kind: 'suppress', target: 'cam-1', args: { a: 2, b: 1, c: undefined } });
  append(log, { ts: 3_000, kind: 'annotate', operator: null, args: { note: 'x' } });
  const ordered = createAuditLog();
  append(ordered, {
    ts: 1_000,
    kind: 'allow',
    operator: 'alice',
    target: 'cam-1',
    args: { a: 2, b: 1 },
  });
  assert.strictEqual(log.records[0].argsDigest, ordered.records[0].argsDigest);
  assert.strictEqual(log.records[0].argsDigest, log.records[1].argsDigest);
  assert.notStrictEqual(
    log.records[0].argsDigest,
    append(createAuditLog(), { ts: 1_000, kind: 'allow', args: { a: 3 } }).argsDigest,
  );

  assert.deepStrictEqual(verifyAudit(log), { ok: true });
  const records = auditLog(log, {});
  assert.strictEqual(records.length, 3);
  assert.strictEqual(records[0].seq, 0);
  assert.strictEqual(records[0].prevHash, ZERO);
  assert.strictEqual(records[0].prevHash.length, 64);
  assert.match(records[0].hash, /^[0-9a-f]{64}$/);
  assert.match(records[0].argsDigest, /^[0-9a-f]{16}$/);
  assert.strictEqual(records[1].prevHash, records[0].hash);
  assert.strictEqual(records[2].prevHash, records[1].hash);
  assert.strictEqual(records[2].operator, null);
  assert.strictEqual(records[2].target, null);
  assert.deepStrictEqual(
    auditLog(log, { sinceSeq: 1 }).map((row) => row.seq),
    [1, 2],
  );
  records[0].kind = 'ack';
  assert.deepStrictEqual(verifyAudit(log), { ok: true });

  const copy = createAuditLog();
  fromJSON(copy, toJSON(log));
  assert.deepStrictEqual(verifyAudit(copy), { ok: true });
  assert.strictEqual(copy.records[1].prevHash, copy.records[0].hash);
});

test('every audit kind is accepted', () => {
  const log = createAuditLog();
  for (let i = 0; i < KINDS.length; i += 1) {
    append(log, { ts: i, kind: KINDS[i], operator: 'op', target: 'dev', args: { i } });
  }
  assert.strictEqual(log.records.length, KINDS.length);
  assert.deepStrictEqual(verifyAudit(log), { ok: true });
});

test('untampered 10000-record ring with eviction verifies', () => {
  const log = createAuditLog();
  for (let i = 0; i < 10_000; i += 1) {
    append(log, { ts: i, kind: 'ack', operator: 'op', target: 't', args: { i } });
  }
  assert.strictEqual(log.records.length, 10_000);
  assert.strictEqual(log.anchor, ZERO);
  assert.strictEqual(log.records[0].seq, 0);
  assert.deepStrictEqual(verifyAudit(log), { ok: true });

  const dropped = log.records[0].hash;
  append(log, { ts: 10_000, kind: 'ack', operator: 'op', target: 't', args: { i: 10_000 } });
  assert.strictEqual(log.records.length, 10_000);
  assert.strictEqual(log.records[0].seq, 1);
  assert.strictEqual(log.records[log.records.length - 1].seq, 10_000);
  assert.strictEqual(log.anchor, dropped);
  assert.strictEqual(log.records[0].prevHash, dropped);
  assert.deepStrictEqual(verifyAudit(log), { ok: true });

  for (let i = 0; i < 50; i += 1) {
    append(log, { ts: 10_001 + i, kind: 'lock', operator: 'op', target: 't', args: null });
  }
  assert.strictEqual(log.records.length, 10_000);
  assert.strictEqual(log.records[0].seq, 51);
  assert.strictEqual(log.anchor, log.records[0].prevHash);
  assert.notStrictEqual(log.anchor, ZERO);
  assert.deepStrictEqual(verifyAudit(log), { ok: true });
  assert.strictEqual(auditLog(log, { sinceSeq: 10_050 }).length, 1);
  assert.strictEqual(auditLog(log, { sinceSeq: 10_051 }).length, 0);

  const copy = createAuditLog();
  fromJSON(copy, toJSON(log));
  assert.deepStrictEqual(verifyAudit(copy), { ok: true });
  assert.strictEqual(copy.anchor, log.anchor);
  assert.strictEqual(copy.records.length, 10_000);
});

test('1000 seeded tamper cases are caught', () => {
  const rng = mulberry32(20261021);
  const modes = ['edit', 'delete', 'reorder', 'truncate'];
  /** @type {Record<string, number>} */
  const seen = { edit: 0, delete: 0, reorder: 0, truncate: 0 };
  for (let n = 0; n < 1_000; n += 1) {
    const log = createAuditLog();
    const count = 4 + Math.floor(rng() * 12);
    for (let i = 0; i < count; i += 1) {
      append(log, {
        ts: Math.floor(rng() * 1e9),
        kind: KINDS[Math.floor(rng() * KINDS.length)],
        operator: `op-${Math.floor(rng() * 10)}`,
        target: `dev-${Math.floor(rng() * 10)}`,
        args: { n, i },
      });
    }
    assert.deepStrictEqual(verifyAudit(log), { ok: true });
    const mode = modes[Math.floor(rng() * modes.length)];
    seen[mode] += 1;
    const idx = Math.floor(rng() * log.records.length);
    const record = log.records[idx];
    if (mode === 'edit') {
      const field = Math.floor(rng() * 6);
      if (field === 0) record.ts += 1;
      else if (field === 1) record.kind = record.kind === 'allow' ? 'ack' : 'allow';
      else if (field === 2) record.operator = `${record.operator}~`;
      else if (field === 3) record.target = `${record.target}~`;
      else if (field === 4) record.seq += 1;
      else record.argsDigest = flipHex(record.argsDigest, rng);
    } else if (mode === 'delete') {
      log.records.splice(idx, 1);
    } else if (mode === 'reorder') {
      let other = Math.floor(rng() * (log.records.length - 1));
      if (other >= idx) other += 1;
      const swap = log.records[idx];
      log.records[idx] = log.records[other];
      log.records[other] = swap;
    } else {
      const field = rng() < 0.5 ? 'hash' : 'prevHash';
      record[field] = record[field].slice(0, -1);
    }
    const result = verifyAudit(log);
    assert.strictEqual(result.ok, false, `${mode} case ${n}`);
    assert.strictEqual(Number.isInteger(result.brokenAt), true, `${mode} case ${n}`);
  }
  for (const mode of modes) assert.ok(seen[mode] > 0, mode);
});

test('HMAC chain verifies and a different key does not extend it', () => {
  const plain = createAuditLog();
  const keyed = createAuditLog();
  const input = { ts: 3, kind: 'feedback', operator: 'engine', target: 'd', args: { score: 1 } };
  append(plain, input);
  append(keyed, input, { key: 'checkpoint-key' });
  append(keyed, { ts: 4, kind: 'promote', operator: 'engine', target: 'd', args: [1, 2] });
  assert.notStrictEqual(plain.records[0].hash, keyed.records[0].hash);
  assert.strictEqual(plain.records[0].argsDigest, keyed.records[0].argsDigest);
  assert.deepStrictEqual(verifyAudit(keyed), { ok: true });
  assert.throws(
    () => append(keyed, { ts: 5, kind: 'promote', args: {} }, { key: 'other' }),
    codeIs('AUDIT_KEY_IS_INVALID'),
  );
  assert.strictEqual(keyed.records.length, 2);
  assert.deepStrictEqual(verifyAudit(keyed), { ok: true });

  const loaded = createAuditLog();
  fromJSON(loaded, toJSON(keyed));
  assert.deepStrictEqual(verifyAudit(loaded), { ok: true });
  loaded.key = null;
  assert.strictEqual(verifyAudit(loaded).ok, false);

  const open = createAuditLog();
  append(open, { ts: 0, kind: 'ack', args: {} });
  assert.throws(
    () => append(open, { ts: 1, kind: 'ack', args: {} }, { key: 'late' }),
    codeIs('AUDIT_KEY_IS_INVALID'),
  );
  assert.strictEqual(open.records.length, 1);
  assert.deepStrictEqual(verifyAudit(open), { ok: true });
});

test('bad input throws and does not mutate', () => {
  const log = createAuditLog();
  append(log, { ts: 1, kind: 'allow', operator: 'a', target: 'b', args: { port: 1 } });
  const before = toJSON(log);
  assert.throws(
    () => append(log, { ts: 2, kind: 'nope', args: {} }),
    codeIs('AUDIT_KIND_IS_INVALID'),
  );
  assert.throws(() => append(log, { kind: 'allow' }), codeIs('AUDIT_TS_IS_INVALID'));
  assert.throws(() => append(log, JSON.parse('{"__proto__":{"x":1},"ts":2,"kind":"allow"}')));
  assert.throws(() =>
    append(log, { ts: 2, kind: 'allow', args: JSON.parse('{"__proto__":{"polluted":true}}') }),
  );
  const inherited = { ts: 2, kind: 'allow', args: {} };
  inherited['__proto__'] = { polluted: true };
  assert.throws(() => append(log, inherited));
  assert.throws(() => fromJSON(log, { records: [{ seq: 0 }] }), codeIs('AUDIT_STATE_IS_INVALID'));
  assert.throws(() => fromJSON(log, null), codeIs('AUDIT_STATE_IS_INVALID'));
  assert.deepStrictEqual(toJSON(log), before);
  assert.strictEqual(Object.hasOwn(Object.prototype, 'polluted'), false);
  assert.strictEqual(Object.hasOwn(Object.prototype, 'x'), false);
  assert.deepStrictEqual(verifyAudit(log), { ok: true });
});

/**
 * @param {string} text
 * @param {() => number} rng
 * @returns {string}
 */
function flipHex(text, rng) {
  const alphabet = '0123456789abcdef';
  const pos = Math.floor(rng() * text.length);
  const index = alphabet.indexOf(text.charAt(pos));
  const next = alphabet[(index + 1) % 16];
  return text.slice(0, pos) + next + text.slice(pos + 1);
}

test('mutated log fields and bad snapshots are rejected', () => {
  const log = createAuditLog();
  log.anchor = 1;
  assert.throws(
    () => append(log, { ts: 1, kind: 'allow', args: {} }),
    codeIs('AUDIT_STATE_IS_INVALID'),
  );
  log.anchor = ZERO;
  log.nextSeq = -1;
  assert.throws(
    () => append(log, { ts: 1, kind: 'allow', args: {} }),
    codeIs('AUDIT_SEQ_IS_INVALID'),
  );
  log.nextSeq = Number.MAX_SAFE_INTEGER;
  assert.throws(
    () => append(log, { ts: 1, kind: 'allow', args: {} }),
    codeIs('AUDIT_SEQ_IS_INVALID'),
  );
  log.nextSeq = 0;
  log.records = [{ seq: 'nope' }];
  assert.throws(() => auditLog(log, {}), codeIs('AUDIT_SEQ_IS_INVALID'));
  log.records = [];
  log.nextSeq = -1;
  assert.deepStrictEqual(verifyAudit(log), { ok: false, brokenAt: 0 });
  log.records = new Array(10001);
  log.nextSeq = 0;
  assert.deepStrictEqual(verifyAudit(log), { ok: false, brokenAt: 0 });
  assert.throws(
    () => append({}, { ts: 1, kind: 'allow', args: {} }),
    codeIs('AUDIT_LOG_IS_INVALID'),
  );
  assert.throws(
    () => append(createAuditLog(), { ts: 1, kind: 'allow', args: {} }, []),
    codeIs('AUDIT_KEY_IS_INVALID'),
  );
  assert.throws(
    () => append(createAuditLog(), { ts: 1, kind: 'allow', args: {} }, { key: 1 }),
    codeIs('AUDIT_KEY_IS_INVALID'),
  );
  assert.throws(
    () => append(createAuditLog(), { ts: 1, kind: 'allow', args: {} }, { extra: true }),
    codeIs('AUDIT_KEY_IS_INVALID'),
  );
  assert.throws(() => fromJSON(createAuditLog(), null), codeIs('AUDIT_STATE_IS_INVALID'));
  assert.throws(() => fromJSON({}, {}), codeIs('AUDIT_LOG_IS_INVALID'));
  const good = toJSON(createAuditLog());
  good.records = [null];
  assert.throws(() => fromJSON(createAuditLog(), good), codeIs('AUDIT_RECORD_IS_INVALID'));
  good.records = [{ seq: 0 }];
  assert.throws(() => fromJSON(createAuditLog(), good), codeIs('AUDIT_RECORD_IS_INVALID'));
});
