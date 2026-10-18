'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { fanout } = require('../../../../test/fixtures/attacks');
const { simulate } = require('../../../../test/fixtures/sim');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

test('fan-out fires once when a window exceeds the learned limit', () => {
  const engine = createEngine({ learnMs: 7 * DAY });
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'fan-out') alerts.push(item);
  });
  for (const event of simulate({ profile: 'camera', days: 7, seed: 3, startTs: T0 }))
    engine.feed(event);
  const ts = T0 + 7 * DAY + 12 * H;
  for (const event of fanout('camera-1', ts, 40)) engine.feed(event);
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'high');
  assert.match(alerts[0].actual, /hosts\/window$/);
});

test('fan-out keeps a running summary instead of the window list', () => {
  const engine = createEngine({ learnMs: 10_000_000, windowMs: 1000, maxWindows: 4 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.flush(20_000);
  const state = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['fan-out'].state;
  assert.strictEqual(state.samples, undefined);
  assert.ok(state.count > 4);
});

test('fan-out limit follows an imported baseline', () => {
  const engine = createEngine({ learnMs: 60_000, windowMs: 60_000, minFanout: 10 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.flush(60_000);
  const copy = createEngine({ learnMs: 60_000, windowMs: 60_000, minFanout: 10 });
  const alerts = [];
  copy.on('anomaly', (item) => {
    if (item.detector === 'fan-out') alerts.push(item);
  });
  copy.importBaseline(engine.exportBaseline({ createdAt: 1 }));
  for (const event of fanout('d', 120_000, 12)) copy.feed(event);
  assert.strictEqual(alerts.length, 1);
});
