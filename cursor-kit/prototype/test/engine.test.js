'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const H = 3600e3;
const DAY = 24 * H;
const T0 = Date.UTC(2026, 0, 5, 0, 0, 0); // midnight UTC

// A camera: active 08:00-20:00, talks to 2 vendor hosts, ~2 KB per minute.
function learnCamera(engine, days = 7) {
  for (let day = 0; day < days; day++) {
    for (let h = 8; h < 20; h++) {
      for (let m = 0; m < 60; m += 5) {
        const ts = T0 + day * DAY + h * H + m * 60e3;
        engine.feed({ device: 'cam-1', dst: m % 10 ? 'video.vendor.com' : 'time.vendor.com', bytes: 2000, ts });
      }
    }
  }
}

function collect(engine) {
  const out = [];
  engine.on('anomaly', (e) => out.push(e));
  return out;
}

test('normal week after learning produces no alerts', () => {
  const e = createEngine({ learnMs: 7 * DAY });
  const alerts = collect(e);
  learnCamera(e, 14); // 7 learn + 7 normal
  e.flush();
  assert.deepStrictEqual(alerts, []);
});

test('catches a new destination', () => {
  const e = createEngine({ learnMs: 7 * DAY });
  const alerts = collect(e);
  learnCamera(e);
  e.feed({ device: 'cam-1', dst: 'evil.example', bytes: 100, ts: T0 + 7 * DAY + 10 * H });
  assert.ok(alerts.some((a) => a.detector === 'new-destination' && a.actual === 'evil.example'));
});

test('catches Mirai-style fan-out', () => {
  const e = createEngine({ learnMs: 7 * DAY });
  const alerts = collect(e);
  learnCamera(e);
  const ts = T0 + 7 * DAY + 10 * H;
  for (let i = 0; i < 500; i++) e.feed({ device: 'cam-1', dst: `10.0.${i >> 8}.${i & 255}`, bytes: 60, ts: ts + i });
  assert.strictEqual(alerts.filter((a) => a.detector === 'fan-out').length, 1);
});

test('catches a volume spike', () => {
  const e = createEngine({ learnMs: 7 * DAY });
  const alerts = collect(e);
  learnCamera(e);
  const ts = T0 + 7 * DAY + 10 * H;
  e.feed({ device: 'cam-1', dst: 'video.vendor.com', bytes: 50e6, ts });
  e.flush();
  assert.ok(alerts.some((a) => a.detector === 'volume-spike'));
});

test('catches 3 a.m. activity', () => {
  const e = createEngine({ learnMs: 7 * DAY });
  const alerts = collect(e);
  learnCamera(e);
  e.feed({ device: 'cam-1', dst: 'video.vendor.com', bytes: 2000, ts: T0 + 8 * DAY + 3 * H });
  assert.ok(alerts.some((a) => a.detector === 'wrong-time'));
});

test('baseline export/import keeps detection', () => {
  const a = createEngine({ learnMs: 7 * DAY });
  learnCamera(a);
  a.flush();
  const b = createEngine();
  const alerts = collect(b);
  b.importBaseline(JSON.parse(JSON.stringify(a.exportBaseline())));
  b.feed({ device: 'cam-1', dst: 'evil.example', bytes: 1, ts: T0 + 8 * DAY + 10 * H });
  assert.ok(alerts.some((x) => x.detector === 'new-destination'));
});
