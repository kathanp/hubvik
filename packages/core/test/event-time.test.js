'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

/**
 * @param {number} skew
 * @param {number} reorderMs
 */
function run(skew, reorderMs) {
  const engine = createEngine({ learnMs: 0, reorderMs });
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any[]} */
  const warnings = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 1_000_000 - skew });
  return { anomalies, warnings, watermark: engine.stats().watermark };
}

test('two adapters with a 2s skew match the sorted stream', () => {
  const skewed = run(2_000, 5_000);
  const sorted = createEngine({ learnMs: 0, reorderMs: 5_000 });
  /** @type {any[]} */
  const anomalies = [];
  sorted.on('anomaly', (item) => anomalies.push(item));
  sorted.feedBatch([
    { device: 'd', dst: 'a.example', bytes: 10, ts: 1_000_000 },
    { device: 'd', dst: 'b.example', bytes: 10, ts: 998_000 },
  ]);
  assert.deepStrictEqual(
    skewed.warnings.map((warning) => warning.code),
    [],
  );
  assert.deepStrictEqual(
    skewed.anomalies.map((item) => `${item.detector}:${item.actual}`).sort(),
    anomalies.map((item) => `${item.detector}:${item.actual}`).sort(),
  );
  assert.strictEqual(skewed.watermark, 1_000_000);
});

test('a 10s skew is one clock jump and the event is not learned', () => {
  const engine = createEngine({ learnMs: 86_400_000, reorderMs: 5_000 });
  /** @type {any[]} */
  const warnings = [];
  /** @type {any[]} */
  const anomalies = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 60_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 50_000 });
  engine.flush();
  assert.ok(warnings.some((warning) => warning.code === 'CLOCK_JUMP'));
  assert.strictEqual(anomalies.filter((item) => item.detector === 'clock-jump').length, 1);
  const learned = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination']
    .state.dsts;
  assert.deepStrictEqual(learned, ['a.example']);
});

test('a backward step inside the open window is not a clock jump', () => {
  const engine = createEngine({ learnMs: 86_400_000, reorderMs: 0 });
  /** @type {any[]} */
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 10_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 1_000 });
  assert.deepStrictEqual(
    warnings.map((warning) => warning.code),
    [],
  );
  const learned = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination']
    .state.dsts;
  assert.deepStrictEqual(learned.sort(), ['a.example', 'b.example']);
});

test('flush drains the watermark window and flush(now) does not', () => {
  const drained = createEngine({ learnMs: 0 });
  /** @type {any[]} */
  const drainedAlerts = [];
  drained.on('anomaly', (item) => drainedAlerts.push(item));
  drained.feed({ device: 'd', dst: 'a.example', bytes: 50e6, ts: 10_000 });
  drained.flush();
  assert.ok(drainedAlerts.some((item) => item.detector === 'volume-spike'));

  const held = createEngine({ learnMs: 0 });
  /** @type {any[]} */
  const heldAlerts = [];
  held.on('anomaly', (item) => heldAlerts.push(item));
  held.feed({ device: 'd', dst: 'a.example', bytes: 50e6, ts: 10_000 });
  held.flush(10_000);
  assert.deepStrictEqual(
    heldAlerts.filter((item) => item.detector === 'volume-spike'),
    [],
  );
});

test('an event after a drain into a closed window is late', () => {
  const engine = createEngine({ learnMs: 86_400_000, reorderMs: 5_000 });
  /** @type {any[]} */
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 10_000 });
  engine.flush();
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 20_000 });
  assert.ok(warnings.some((warning) => warning.code === 'LATE_EVENT'));
  const learned = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination']
    .state.dsts;
  assert.deepStrictEqual(learned, ['a.example']);
});

test('an event older than the open window is dropped and does not reopen it', () => {
  const engine = createEngine({ learnMs: 86_400_000, windowMs: 60_000, reorderMs: 5_000 });
  /** @type {any[]} */
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 120_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 10_000 });
  engine.flush();
  assert.ok(warnings.some((warning) => warning.code === 'LATE_EVENT'));
  const dsts = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination'].state
    .dsts;
  assert.deepStrictEqual(dsts, ['a.example']);
  assert.strictEqual(engine.stats().watermark, 120_000);
});
