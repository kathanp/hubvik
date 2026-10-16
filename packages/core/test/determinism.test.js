'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { simulate } = require('../../../test/fixtures/sim');
const { T0, DAY } = require('../../../test/fixtures/clock');

function project(anomalies) {
  return anomalies.map((item) => ({
    id: item.id,
    device: item.device,
    detector: item.detector,
    severity: item.severity,
    ts: item.ts,
    actual: item.actual,
    expected: item.expected,
    confidence: item.confidence,
    data: item.data,
  }));
}

function run(seed) {
  const events = simulate({ profile: 'plug', days: 8, seed, startTs: T0 });
  const engine = createEngine({ learnMs: 7 * DAY, windowMs: 60_000 });
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  for (const event of events) engine.feed(event);
  const ts = T0 + 8 * DAY;
  engine.feed({ device: 'plug-1', dst: 'evil.example', bytes: 100, ts });
  engine.flush(ts + 60_000);
  return project(anomalies);
}

test('the same seed produces the same anomaly stream', () => {
  assert.deepStrictEqual(run(4), run(4));
});

test('two seeds produce different benign event streams', () => {
  const a = simulate({ profile: 'camera', days: 1, seed: 1, startTs: T0 });
  const b = simulate({ profile: 'camera', days: 1, seed: 2, startTs: T0 });
  assert.notDeepStrictEqual(a, b);
});
