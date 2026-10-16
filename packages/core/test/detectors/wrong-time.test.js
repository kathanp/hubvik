'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

test('wrong-time fires off schedule and stays quiet inside learned hours', () => {
  const engine = createEngine({ learnMs: 7 * DAY });
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'wrong-time') alerts.push(item);
  });
  for (const event of simulate({ profile: 'tv-box', days: 8, seed: 1, startTs: T0 }))
    engine.feed(event);
  engine.flush(T0 + 8 * DAY);
  assert.strictEqual(alerts.length, 0);
  const ts = T0 + 8 * DAY + 3 * H;
  engine.feed({ device: 'tv-1', dst: 'cdn-0.video.example', bytes: 1000, ts });
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'low');
  assert.match(alerts[0].actual, /active at hour 3/);
});

test('wrong-time dedup keys stay inside the alert cap', () => {
  const engine = createEngine({ learnMs: 1, maxAlertKeys: 2 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 8 * H });
  engine.lock('d');
  for (let day = 1; day <= 4; day++) {
    engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: day * DAY + 3 * H });
  }
  const seen = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['wrong-time'].state.seen;
  assert.strictEqual(seen.length, 2);
});

test('wrong-time hours survive export and import', () => {
  const engine = createEngine({ learnMs: 1 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 8 * H });
  engine.lock('d');
  const copy = createEngine({ learnMs: 1 });
  const alerts = [];
  copy.on('anomaly', (item) => {
    if (item.detector === 'wrong-time') alerts.push(item);
  });
  copy.importBaseline(engine.exportBaseline({ createdAt: 1 }));
  copy.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: DAY + 3 * H });
  copy.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: DAY + 8 * H });
  assert.strictEqual(alerts.length, 1);
});
