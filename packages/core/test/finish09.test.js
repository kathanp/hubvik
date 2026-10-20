'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine, detectors } = require('../src/index.js');
const { mulberry32 } = require('../../../test/fixtures/prng');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');

/**
 * @param {Record<string, unknown>} [extra]
 */
function engine(extra = {}) {
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const id of Object.keys(detectors)) off[id] = { enabled: false };
  return createEngine({
    learnMs: 60_000,
    tiers: ['T0', 'T1', 'T2', 'T3', 'T5'],
    detectors: off,
    ...extra,
  });
}

test('budget sheds T5 before a hard rule and can recover', () => {
  let now = 0n;
  const clock = () => {
    const value = now;
    now += 1_000_000n;
    return value;
  };
  const box = engine({
    learnMs: 0,
    budget: { perEventUs: 50, sampleEvery: 1, recoverWindows: 1, clock },
    tiers: ['T5'],
  });
  let soft = 0;
  let hard = 0;
  /** @type {string[]} */
  const warnings = [];
  box.on('anomaly', (/** @type {any} */ row) => {
    if (row.detector === 'soft-tier') soft += 1;
    if (row.detector === 'hard-tier') hard += 1;
  });
  box.on('warning', (/** @type {any} */ row) => warnings.push(row.code));
  box.use({
    id: 'soft-tier',
    version: 1,
    requires: ['T5'],
    defaults: { severity: 'low' },
    createState() {
      return {};
    },
    check(_state, ev) {
      return { severity: 'low', confidence: 0.5, ts: ev.ts, actual: 'soft', expected: 'quiet' };
    },
  });
  box.use({
    id: 'hard-tier',
    version: 1,
    requires: ['T5'],
    hardRule: true,
    defaults: { severity: 'high' },
    createState() {
      return {};
    },
    check(_state, ev) {
      return { severity: 'high', confidence: 0.5, ts: ev.ts, actual: 'hard', expected: 'quiet' };
    },
  });
  const event = { device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 };
  box.feed(event);
  box.feed({ ...event, ts: 2_000 });
  assert.ok(soft >= 1);
  assert.ok(hard >= 2);
  assert.ok(warnings.includes('DEGRADED'));
  assert.ok(box.stats().shed.includes('soft-tier'));
  assert.ok(!box.stats().shed.includes('hard-tier'));
});

test('checkpoint delta restores the later baseline and rejects a tampered delta', () => {
  const box = engine();
  box.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  const saved = box.checkpoint({ createdAt: 1 });
  box.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 2_000 });
  const delta = box.checkpointDelta(0);
  const end = box.exportBaseline({ createdAt: 1 });
  const next = engine();
  next.restore(saved);
  next.applyDelta(delta);
  assert.deepStrictEqual(next.exportBaseline({ createdAt: 1 }), end);
  const bad = { ...delta, watermark: 1 };
  assert.throws(() => engine().applyDelta(bad), /hash/);
  assert.throws(() => next.applyDelta(delta), /out of order/);
});

test('time zone changes the learned hour and redact leaves the baseline raw', () => {
  const ts = Date.parse('2026-01-15T18:00:00Z');
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const id of Object.keys(detectors)) if (id !== 'wrong-time') off[id] = { enabled: false };
  const utc = createEngine({ learnMs: 1e12, tiers: ['T0'], detectors: off });
  const zoned = createEngine({ learnMs: 1e12, tiers: ['T0'], detectors: off });
  zoned.setDeviceTimezone('cam', 'America/Chicago');
  assert.throws(() => zoned.setDeviceTimezone('cam', 'Not/AZone'), /time zone/);
  const event = { device: 'cam', dst: 'a.example', bytes: 10, ts };
  utc.feed(event);
  zoned.feed(event);
  const utcHours = utc.exportBaseline().devices.cam.detectors['wrong-time'].state.hours;
  const zonedHours = zoned.exportBaseline().devices.cam.detectors['wrong-time'].state.hours;
  assert.deepStrictEqual(utcHours, [18]);
  assert.deepStrictEqual(zonedHours, [12]);

  const red = createEngine({
    learnMs: 0,
    tiers: ['T0'],
    redact: { key: 'secret', fields: ['device', 'dst'] },
  });
  /** @type {any[]} */
  const anomalies = [];
  red.on('anomaly', (row) => anomalies.push(row));
  red.use({
    id: 'red-demo',
    version: 1,
    requires: ['T0'],
    defaults: { severity: 'low' },
    createState() {
      return {};
    },
    check(_state, ev) {
      return {
        severity: 'low',
        confidence: 0.5,
        ts: ev.ts,
        actual: ev.dst,
        expected: 'quiet',
        data: { dst: ev.dst },
      };
    },
  });
  red.feed(event);
  assert.ok(String(anomalies[0].device).startsWith('r_'));
  assert.strictEqual(red.exportBaseline({ createdAt: 1 }).devices.cam.peerGroup, null);
});

test('calibrated confidence, class suggestion, and response hints stay off by default', () => {
  const plain = engine({ learnMs: 0 });
  /** @type {any[]} */
  const rows = [];
  plain.on('anomaly', (row) => rows.push(row));
  plain.use({
    id: 'margin-demo',
    version: 1,
    requires: ['T0'],
    defaults: { severity: 'low' },
    createState() {
      return {};
    },
    check(_state, ev) {
      return {
        severity: 'low',
        confidence: 0.2,
        margin: 1,
        ts: ev.ts,
        actual: 'x',
        expected: 'y',
      };
    },
  });
  plain.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  assert.strictEqual(rows[0].confidence, 0.2);
  assert.strictEqual(rows[0].response, undefined);

  const on = engine({
    learnMs: 1e12,
    calibratedConfidence: true,
    responseHints: true,
    classSuggest: true,
  });
  /** @type {any[]} */
  const hinted = [];
  /** @type {string[]} */
  const warnings = [];
  on.on('anomaly', (row) => hinted.push(row));
  on.on('warning', (/** @type {any} */ row) => warnings.push(row.code));
  on.use({
    id: 'margin-demo',
    version: 1,
    requires: ['T0'],
    defaults: { severity: 'low' },
    createState() {
      return {};
    },
    check(_state, ev) {
      return { severity: 'low', confidence: 0.2, margin: 1, ts: ev.ts, actual: 'x', expected: 'y' };
    },
    learn(_state, ev) {
      return { severity: 'low', confidence: 0.2, margin: 1, ts: ev.ts, actual: 'x', expected: 'y' };
    },
  });
  on.feed({
    type: 'app',
    device: 'hvac',
    ts: 1_000,
    proto: 'bacnet',
    role: 'server',
    peerIp: '192.0.2.20',
    op: 'read',
  });
  on.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 2_000 });
  assert.strictEqual(hinted[0].confidence, 0.5);
  assert.ok(warnings.includes('CLASS_SUGGESTED'));
});

test('budget sheds T5, then T3, T2, T1, and T0, and never sheds a hard rule', () => {
  let now = 0n;
  const clock = () => {
    const value = now;
    now += 1_000_000n;
    return value;
  };
  const box = engine({
    learnMs: 0,
    budget: { perEventUs: 50, sampleEvery: 1, recoverWindows: 5, clock },
    tiers: ['T0', 'T1', 'T2', 'T3', 'T5'],
  });
  /** @type {Record<string, number>} */
  const fired = {};
  /** @type {string[][]} */
  const shed = [];
  box.on('anomaly', (/** @type {any} */ row) => {
    fired[row.detector] = (fired[row.detector] || 0) + 1;
  });
  box.on('warning', (/** @type {any} */ row) => {
    if (row.code === 'DEGRADED') shed.push(row.shed.slice());
  });
  const order = ['T5', 'T3', 'T2', 'T1', 'T0'];
  for (const tier of order) {
    box.use({
      id: `soft-${tier.toLowerCase()}`,
      version: 1,
      requires: [tier],
      defaults: { severity: 'low' },
      createState() {
        return {};
      },
      check(_state, ev) {
        return { severity: 'low', confidence: 0.5, ts: ev.ts, actual: tier, expected: 'quiet' };
      },
    });
  }
  box.use({
    id: 'hard-t5',
    version: 1,
    requires: ['T5'],
    hardRule: true,
    defaults: { severity: 'high' },
    createState() {
      return {};
    },
    check(_state, ev) {
      return { severity: 'high', confidence: 0.5, ts: ev.ts, actual: 'hard', expected: 'quiet' };
    },
  });
  for (let i = 1; i <= 5; i += 1) {
    box.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: i * 1_000 });
  }
  assert.deepStrictEqual(
    shed.map((ids) => ids.filter((id) => id.startsWith('soft-'))),
    [
      ['soft-t5'],
      ['soft-t5', 'soft-t3'],
      ['soft-t5', 'soft-t3', 'soft-t2'],
      ['soft-t5', 'soft-t3', 'soft-t2', 'soft-t1'],
      ['soft-t5', 'soft-t3', 'soft-t2', 'soft-t1', 'soft-t0'],
    ],
  );
  assert.strictEqual(fired['soft-t5'], 1);
  assert.strictEqual(fired['soft-t0'], 5);
  assert.strictEqual(fired['hard-t5'], 5);
  assert.ok(!box.stats().shed.includes('hard-t5'));
});

test('signed checkpoint deltas restore the stream, and 1000 bad deltas leave state unchanged', () => {
  const key = 'delta-key';
  const box = engine();
  box.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  const saved = box.checkpoint({ createdAt: 1 });
  const first = box.checkpointDelta(0, { sign: key });
  box.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 2_000 });
  const second = box.checkpointDelta(first.toSeq, { sign: key });
  const end = box.exportBaseline({ createdAt: 1 });
  const next = engine();
  next.restore(saved);
  next.applyDelta(first, { sign: key });
  next.applyDelta(second, { sign: key });
  assert.deepStrictEqual(next.exportBaseline({ createdAt: 1 }), end);
  assert.throws(() => next.applyDelta(second, { sign: key }), /out of order/);
  const hold = engine();
  hold.restore(saved);
  hold.applyDelta(first, { sign: key });
  const before = hold.exportBaseline({ createdAt: 1 });
  assert.throws(() => hold.applyDelta(second, { sign: 'other' }), /hash/);
  const rng = mulberry32(20261020);
  for (let i = 0; i < 1000; i += 1) {
    const bad = { ...second, watermark: second.watermark + 1 + Math.floor(rng() * 1_000_000) };
    assert.throws(() => hold.applyDelta(bad, { sign: key }), /hash/);
  }
  assert.deepStrictEqual(hold.exportBaseline({ createdAt: 1 }), before);
});

test('deltas every five minutes match a full checkpoint on 14 benign days', () => {
  for (const profile of CLASS_NAMES) {
    const events = simulate({ profile, days: 14, seed: 1 });
    const opts = { learnMs: 86_400_000, tiers: ['T0'] };
    const full = createEngine(opts);
    for (const event of events) full.feed(event);
    full.flush(events[events.length - 1].ts + 60_000);
    const end = full.exportBaseline({ createdAt: 1 });
    const src = createEngine(opts);
    const next = createEngine(opts);
    src.feed(events[0]);
    next.restore(src.checkpoint({ createdAt: 1 }));
    let delta = src.checkpointDelta(0);
    next.applyDelta(delta);
    let since = delta.toSeq;
    let mark = events[0].ts;
    for (let i = 1; i < events.length; i += 1) {
      src.feed(events[i]);
      if (events[i].ts - mark >= 300_000 || i === events.length - 1) {
        delta = src.checkpointDelta(since);
        next.applyDelta(delta);
        since = delta.toSeq;
        mark = events[i].ts;
      }
    }
    next.flush(events[events.length - 1].ts + 60_000);
    assert.deepStrictEqual(next.exportBaseline({ createdAt: 1 }), end);
  }
});

test('federation summaries hide device ids and stop at 1000', () => {
  const box = engine({ learnMs: 0 });
  box.setPeerGroup('camera-1', 'kitchen');
  box.feed({ device: 'camera-1', dst: 'a.example', bytes: 10, ts: 1_000 });
  const summary = box.exportSummary({ key: 'summary-key', gatewayId: 'gw-a' });
  const text = JSON.stringify(summary);
  assert.strictEqual(summary.gatewayId, 'gw-a');
  assert.ok(summary.sig && summary.sig.mac);
  assert.ok(!text.includes('camera-1'));
  assert.ok(!text.includes('kitchen'));
  const many = [];
  for (let i = 0; i < 1001; i += 1) many.push({ gatewayId: `gw-${i}`, ts: 1_000, groups: [] });
  assert.throws(() => box.importPeerSummaries(many, { verify: 'summary-key' }), /cap/);
});

test('inline shards match a single engine, and workers are refused', () => {
  assert.throws(() => createShardedEngine({ shards: 4, inline: false }), /Raspberry Pi 4/);
  const events = [
    { device: 'a', dst: 'one.example', bytes: 10, ts: 1_000 },
    { device: 'b', dst: 'two.example', bytes: 10, ts: 2_000 },
  ];
  /** @param {any} box */
  function run(box) {
    /** @type {string[]} */
    const found = [];
    box.on('anomaly', (/** @type {any} */ row) => found.push(`${row.fingerprint}:${row.ts}`));
    for (const event of events) box.feed(event);
    box.flush(60_000);
    return found.sort();
  }
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const id of Object.keys(detectors)) {
    if (id !== 'new-destination') off[id] = { enabled: false };
  }
  const opts = { learnMs: 0, tiers: ['T0'], detectors: off };
  const single = run(createEngine(opts));
  const sharded = run(createShardedEngine({ ...opts, shards: 4, inline: true }));
  assert.deepStrictEqual(sharded, single);
});
