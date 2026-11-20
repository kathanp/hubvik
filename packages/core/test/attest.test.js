'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createHash } = require('node:crypto');
const {
  createEngine,
  createShardedEngine,
  verifyAttestation,
  HubvikError,
} = require('../src/index.js');
const { canonical } = require('../src/engine/baseline.js');
const { version } = require('../package.json');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const KEY = 'attest-key';
const BENCH = [
  'bench median 3.46 µs, estimate 2.29 KB/device, retained 9.61 KB/device, devices 1000',
];

/**
 * @param {object} opts
 * @param {object[]} [events]
 */
function attest(opts, events = []) {
  const engine = createEngine(opts);
  for (const event of events) engine.feed(event);
  return engine.attest({ key: KEY, bench: BENCH });
}

test('attest signs the self-test and leaves the live engine alone', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  /** @type {any[]} */
  const live = [];
  engine.on('anomaly', (row) => live.push(row));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  const before = JSON.stringify(engine.exportBaseline({ createdAt: 1 }));
  const seen = live.length;
  const doc = engine.attest({ key: KEY, bench: BENCH });
  assert.strictEqual(JSON.stringify(engine.exportBaseline({ createdAt: 1 })), before);
  assert.strictEqual(live.length, seen);
  assert.strictEqual(doc.v, 1);
  assert.strictEqual(doc.engine, version);
  assert.strictEqual(doc.sig.alg, 'HMAC-SHA256');
  assert.deepStrictEqual(doc.bench, BENCH);
  assert.deepStrictEqual(Object.keys(doc).sort(), [
    'bench',
    'coverage',
    'engine',
    'optionsHash',
    'scenarios',
    'sig',
    'v',
  ]);
  assert.strictEqual(JSON.stringify(doc).includes('detection'), false);
  const scan = doc.scenarios.find((row) => row.scenario === 'horizontal scan');
  const tunnel = doc.scenarios.find((row) => row.scenario === 'DNS tunnel');
  assert.ok(scan && tunnel);
  assert.strictEqual(scan.status, 'blind');
  assert.strictEqual(tunnel.status, 'blind');
  assert.strictEqual(verifyAttestation(doc, KEY), true);
  assert.strictEqual(verifyAttestation(doc, 'other'), false);
});

test('the same events and options produce the same fired and blind lists', () => {
  const opts = { learnMs: 0, tiers: TIERS };
  const events = [{ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 }];
  const first = attest(opts, events);
  const second = attest(opts, events);
  assert.deepStrictEqual(first, second);
  assert.strictEqual(first.optionsHash, second.optionsHash);
  for (const row of first.scenarios) assert.strictEqual(row.status, 'fired', row.scenario);
  const narrow = attest({ learnMs: 0, tiers: ['T0'] }, events);
  assert.notDeepStrictEqual(
    first.scenarios.map((row) => row.status),
    narrow.scenarios.map((row) => row.status),
  );
  const raw = createEngine(opts).opts.raw;
  const hash = createHash('sha256').update(canonical(raw)).digest('hex');
  assert.strictEqual(first.optionsHash, hash);
});

test('verifyAttestation rejects a tampered hash, a rate field, and a bad signature', () => {
  const doc = attest({ learnMs: 0, tiers: ['T0'] });
  const hash = JSON.parse(JSON.stringify(doc));
  hash.optionsHash = 'a'.repeat(64);
  assert.strictEqual(verifyAttestation(hash, KEY), false);
  const rate = JSON.parse(JSON.stringify(doc));
  rate.detectionRate = 1;
  assert.strictEqual(verifyAttestation(rate, KEY), false);
  const dashed = JSON.parse(JSON.stringify(doc));
  dashed['detection-rate'] = 1;
  assert.strictEqual(verifyAttestation(dashed, KEY), false);
  const mac = JSON.parse(JSON.stringify(doc));
  mac.sig.mac = 'b'.repeat(64);
  assert.strictEqual(verifyAttestation(mac, KEY), false);
  assert.strictEqual(verifyAttestation(doc, Buffer.from(KEY)), true);
  const nasty = JSON.parse(JSON.stringify(doc));
  nasty.constructor = 1;
  assert.strictEqual(verifyAttestation(nasty, KEY), false);
});

test('a bad attest argument throws and changes nothing', () => {
  const engine = createEngine({ learnMs: 0 });
  assert.throws(
    () => engine.attest({ key: 1, bench: [] }),
    (err) => err instanceof HubvikError && err.code === 'ATTEST_KEY_IS_INVALID',
  );
  assert.throws(
    () => engine.attest({ key: KEY, bench: [1] }),
    (err) => err instanceof HubvikError && err.code === 'ATTEST_BENCH_IS_INVALID',
  );
  assert.throws(
    () => engine.attest(null),
    (err) => err instanceof HubvikError && err.code === 'ATTEST_IS_INVALID',
  );
  assert.strictEqual(verifyAttestation(null, KEY), false);
  assert.strictEqual(verifyAttestation({}, KEY), false);
});

test('a sharded engine attest does not feed the shards', () => {
  const box = createShardedEngine({ shards: 2, inline: true, learnMs: 0, tiers: TIERS });
  box.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  const before = box.anomalyCount;
  const doc = box.attest({ key: KEY, bench: [] });
  assert.strictEqual(box.anomalyCount, before);
  assert.strictEqual(verifyAttestation(doc, KEY), true);
  for (const row of doc.scenarios) assert.strictEqual(row.status, 'fired', row.scenario);
  assert.ok(doc.coverage.live + doc.coverage.shadowOnly + doc.coverage.blind > 0);
});
