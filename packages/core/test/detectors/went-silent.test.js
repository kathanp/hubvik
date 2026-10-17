'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

const MIN = 60_000;
const START = Date.UTC(2026, 0, 5, 13, 0, 0);

/**
 * @param {import('../../src/index.js').Engine} engine
 */
function learn(engine) {
  for (let i = 0; i < 9; i++) {
    engine.feed({
      device: 'cam',
      dst: 'video.vendor.com',
      bytes: 100,
      ts: START + i * 5 * MIN,
    });
  }
  engine.lock('cam');
}

test('an unplugged camera alerts once inside its active hour', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3 });
  learn(engine);
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  const last = START + 8 * 5 * MIN;
  engine.tick(Date.UTC(2026, 0, 6, 3, 0, 0));
  assert.strictEqual(anomalies.filter((item) => item.detector === 'went-silent').length, 0);
  engine.tick(last + 16 * MIN);
  engine.tick(last + 20 * MIN);
  const silent = anomalies.filter((item) => item.detector === 'went-silent');
  assert.strictEqual(silent.length, 1);
  assert.match(silent[0].actual, /silent for/);
});

test('a device that keeps its cadence does not alert', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3 });
  learn(engine);
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  const last = START + 8 * 5 * MIN;
  for (let i = 1; i <= 12; i++) {
    const ts = last + i * 5 * MIN;
    engine.feed({ device: 'cam', dst: 'video.vendor.com', bytes: 100, ts });
    engine.tick(ts);
  }
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'went-silent'),
    [],
  );
});

test('forget and a restart at the watermark stay quiet', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3 });
  learn(engine);
  const mark = engine.stats().watermark;
  const saved = JSON.parse(JSON.stringify(engine.exportBaseline()));
  engine.forget('cam');
  engine.tick(mark + 20 * MIN);
  const restarted = createEngine({ learnMs: 7 * 24 * 3600e3 });
  restarted.importBaseline(saved);
  /** @type {any[]} */
  const anomalies = [];
  restarted.on('anomaly', (item) => anomalies.push(item));
  restarted.tick();
  restarted.tick(mark);
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'went-silent'),
    [],
  );
});
