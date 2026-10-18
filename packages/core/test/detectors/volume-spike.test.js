'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { volumeBurst } = require('../../../../test/fixtures/attacks');
const { simulate } = require('../../../../test/fixtures/sim');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

test('volume-spike fires on a burst and stays quiet on the learned rate', () => {
  const engine = createEngine({ learnMs: 7 * DAY });
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'volume-spike') alerts.push(item);
  });
  for (const event of simulate({ profile: 'camera', days: 8, seed: 2, startTs: T0 }))
    engine.feed(event);
  engine.flush(T0 + 8 * DAY);
  assert.strictEqual(alerts.length, 0);
  const ts = T0 + 8 * DAY + H;
  engine.feed(volumeBurst('camera-1', ts, 80_000_000));
  engine.flush(ts + 60_000);
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'high');
  assert.match(alerts[0].actual, /bytes\/window$/);
});

test('volume-spike does not append while watching', () => {
  const engine = createEngine({ learnMs: 60_000, windowMs: 60_000 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 0 });
  engine.flush(60_000);
  engine.lock();
  const before = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['volume-spike'].state
    .count;
  assert.ok(before >= 1);
  engine.feed({ device: 'd', dst: 'a.example', bytes: 5000, ts: 120_000 });
  engine.flush(180_000);
  const after = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['volume-spike'].state
    .count;
  assert.strictEqual(after, before);
});

test('volume-spike keeps a running summary instead of the window list', () => {
  const engine = createEngine({ learnMs: 10_000_000, windowMs: 1000, maxWindows: 4 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.flush(20_000);
  const state = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['volume-spike'].state;
  assert.strictEqual(state.samples, undefined);
  assert.ok(state.count > 4);
  engine.relearn('d', { detectors: ['volume-spike'] });
  const reset = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['volume-spike'].state;
  assert.strictEqual(reset.count, 0);
  assert.strictEqual(reset.mean, 0);
  assert.strictEqual(reset.m2, 0);
  assert.strictEqual(reset.max, 0);
});

test('volume-spike follows an imported baseline', () => {
  const engine = createEngine({ learnMs: 60_000, windowMs: 60_000, minBytes: 1000 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1000, ts: 0 });
  engine.flush(60_000);
  const copy = createEngine({ learnMs: 60_000, windowMs: 60_000, minBytes: 1000 });
  const alerts = [];
  copy.on('anomaly', (item) => {
    if (item.detector === 'volume-spike') alerts.push(item);
  });
  copy.importBaseline(engine.exportBaseline({ createdAt: 1 }));
  copy.feed(volumeBurst('d', 120_000, 5000, 'a.example'));
  copy.flush(180_000);
  assert.strictEqual(alerts.length, 1);
});
