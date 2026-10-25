'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const BIG = 10 * 1024 * 1024 + 1;
const CAP = 4096;
const TTL_MS = 120000;

/**
 * @param {boolean} correlate
 */
function engine(correlate) {
  return createEngine({
    learnMs: 0,
    windowMs: 60000,
    tiers: ['T1', 'T2', 'T3'],
    shadow: ['cloud-storage-exfil'],
    correlate,
  });
}

/**
 * @param {string} uid
 * @param {string} name
 * @param {number} ts
 */
function dns(uid, name, ts) {
  return {
    type: 'dns',
    device: 'cam',
    ts,
    uid,
    qname: name,
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  };
}

/**
 * @param {string} uid
 * @param {number} ts
 * @param {Record<string, unknown>} [extra]
 */
function flow(uid, ts, extra = {}) {
  return {
    type: 'flow',
    device: 'cam',
    ts,
    uid,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: BIG,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 1,
    ...extra,
  };
}

/**
 * @param {import('../src/index.js').Engine} eng
 */
function hits(eng) {
  /** @type {any[]} */
  const rows = [];
  eng.on('shadow-anomaly', (row) => rows.push(row));
  return rows;
}

test('correlate copies a DNS name onto the later flow', () => {
  const eng = engine(true);
  const fired = hits(eng);
  eng.feed(dns('c1', 's3.amazonaws.com', 1));
  eng.feed(flow('c1', 2));
  assert.strictEqual(fired.length, 1);
  assert.strictEqual(fired[0].detector, 'cloud-storage-exfil');
});

test('correlate stays off unless the option is on', () => {
  const eng = engine(false);
  const fired = hits(eng);
  eng.feed(dns('c1', 's3.amazonaws.com', 1));
  eng.feed(flow('c1', 2));
  assert.deepStrictEqual(fired, []);
  assert.strictEqual(eng.checkpoint().correlate, undefined);
});

test('a DNS name replaces an earlier TLS name and a second DNS name does not', () => {
  const replaced = engine(true);
  const replacedHits = hits(replaced);
  replaced.feed({
    type: 'tls',
    device: 'cam',
    ts: 1,
    uid: 'c1',
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 'video.vendor.com',
  });
  replaced.feed(dns('c1', 's3.amazonaws.com', 2));
  replaced.feed(flow('c1', 3));
  assert.strictEqual(replacedHits.length, 1);

  const stuck = engine(true);
  const stuckHits = hits(stuck);
  stuck.feed(dns('c1', 'video.vendor.com', 1));
  stuck.feed(dns('c1', 's3.amazonaws.com', 2));
  stuck.feed(flow('c1', 3));
  assert.deepStrictEqual(stuckHits, []);
});

test('TLS SNI alone is enough, and an existing flow name is kept', () => {
  const eng = engine(true);
  const fired = hits(eng);
  eng.feed({
    type: 'tls',
    device: 'cam',
    ts: 1,
    uid: 'c1',
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 's3.amazonaws.com',
  });
  eng.feed(flow('c1', 2));
  eng.feed(dns('c2', 's3.amazonaws.com', 3));
  eng.feed(flow('c2', 4, { dstName: 'video.vendor.com' }));
  assert.strictEqual(fired.length, 1);
  assert.strictEqual(fired[0].data.name, 's3.amazonaws.com');
});

test('the join expires after 120000 ms and still holds at the boundary', () => {
  const held = engine(true);
  const heldHits = hits(held);
  held.feed(dns('c1', 's3.amazonaws.com', 0));
  held.feed(flow('c1', TTL_MS));
  assert.strictEqual(heldHits.length, 1);

  const expired = engine(true);
  const expiredHits = hits(expired);
  expired.feed(dns('c1', 's3.amazonaws.com', 0));
  expired.feed(flow('c1', TTL_MS + 1));
  assert.deepStrictEqual(expiredHits, []);
});

test('the join table drops the oldest id at 4096', () => {
  const eng = engine(true);
  for (let i = 0; i < CAP; i++) eng.feed(dns(`u${i}`, `h${i}.example`, 1));
  eng.feed(dns('overflow', 'new.example', 1));
  const ids = eng.checkpoint().correlate.map((/** @type {unknown[]} */ row) => row[0]);
  assert.strictEqual(ids.length, CAP);
  assert.strictEqual(ids.includes('u0'), false);
  assert.strictEqual(ids.includes('overflow'), true);
});

test('a checkpoint restores the join, and a bad table is rejected', () => {
  const eng = engine(true);
  eng.feed(dns('c1', 's3.amazonaws.com', 1));
  const saved = eng.checkpoint();
  const next = engine(true);
  const fired = hits(next);
  next.restore(saved);
  next.feed(flow('c1', 2));
  assert.strictEqual(fired.length, 1);

  const bad = engine(true);
  const broken = { ...saved, correlate: [['__proto__', 1, 's3.amazonaws.com', true]] };
  assert.throws(() => bad.restore(broken), /checkpoint correlate is invalid/);
});

test('a default engine ignores a correlate table, and a bad uid is dropped', () => {
  const eng = engine(true);
  eng.feed(dns('c1', 's3.amazonaws.com', 1));
  const saved = eng.checkpoint();
  const plain = engine(false);
  assert.doesNotThrow(() => plain.restore(saved));

  const warned = engine(true);
  /** @type {string[]} */
  const codes = [];
  warned.on('warning', (row) => codes.push(row.code));
  warned.feed({ ...dns('__proto__', 's3.amazonaws.com', 1), uid: '__proto__' });
  warned.feed(flow('__proto__', 2));
  assert.ok(codes.includes('FIELD_DROPPED'));
  assert.strictEqual(warned.checkpoint().correlate, undefined);
});

test('correlate must be a boolean', () => {
  assert.throws(
    () => createEngine({ correlate: 'yes' }),
    (err) => err.code === 'MUST_BE_A_BOOLEAN',
  );
});
