'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

function alertsOf(engine, detector) {
  const out = [];
  engine.on('anomaly', (item) => {
    if (item.detector === detector) out.push(item);
  });
  return out;
}

test('new-destination fires on an unseen host and stays quiet on a learned one', () => {
  const engine = createEngine({ learnMs: 7 * DAY });
  const alerts = alertsOf(engine, 'new-destination');
  for (const event of simulate({ profile: 'camera', days: 7, seed: 1, startTs: T0 }))
    engine.feed(event);
  const ts = T0 + 7 * DAY + 10 * H;
  engine.feed({ device: 'camera-1', dst: 'video.vendor.com', bytes: 100, ts });
  engine.feed({ device: 'camera-1', dst: 'evil.example', bytes: 100, ts: ts + 60_000 });
  assert.deepStrictEqual(
    alerts.map((item) => item.actual),
    ['evil.example'],
  );
});

test('new-destination caps emissions per window and keeps the alerted key', () => {
  const engine = createEngine({ learnMs: 1, maxNewDstPerWindow: 2, maxAlertKeys: 10 });
  const alerts = alertsOf(engine, 'new-destination');
  engine.feed({ device: 'd', dst: 'known.example', bytes: 1, ts: 0 });
  engine.lock('d');
  for (let i = 0; i < 5; i++) {
    engine.feed({ device: 'd', dst: `n${i}.example`, bytes: 1, ts: 120_000 + i });
  }
  assert.deepStrictEqual(
    alerts.map((item) => item.actual),
    ['n0.example', 'n1.example'],
  );
  const state = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination']
    .state;
  assert.ok(state.alerted.includes('n4.example'));
});

test('new-destination survives export and import', () => {
  const engine = createEngine({ learnMs: 1 });
  engine.feed({ device: 'd', dst: 'known.example', bytes: 1, ts: 0 });
  engine.lock('d');
  const copy = createEngine({ learnMs: 1 });
  const alerts = alertsOf(copy, 'new-destination');
  copy.importBaseline(engine.exportBaseline({ createdAt: 1 }));
  copy.feed({ device: 'd', dst: 'known.example', bytes: 1, ts: 120_000 });
  copy.feed({ device: 'd', dst: 'evil.example', bytes: 1, ts: 180_000 });
  assert.deepStrictEqual(
    alerts.map((item) => item.actual),
    ['evil.example'],
  );
});
