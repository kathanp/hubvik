'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { T0, H, DAY } = require('../../../test/fixtures/clock');
const { simulate } = require('../../../test/fixtures/sim');

function take(engine) {
  const anomalies = [];
  const warnings = [];
  const learned = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.on('warning', (item) => warnings.push(item));
  engine.on('learned', (item) => learned.push(item));
  return { anomalies, warnings, learned };
}

test('flush 30s off a boundary matches a boundary flush and does not close early', () => {
  const windowMs = 60_000;
  const start = 10 * windowMs;
  function run(flushAt) {
    const engine = createEngine({ learnMs: 0, windowMs, minBytes: 1000 });
    const bag = take(engine);
    engine.feed({ device: 'd', dst: 'a.example', bytes: 5000, ts: start + 1000 });
    engine.flush(flushAt);
    return bag.anomalies
      .filter((item) => item.detector === 'volume-spike')
      .map((item) => item.actual);
  }
  assert.deepStrictEqual(run(start + windowMs - 30_000), []);
  const onBoundary = run(start + windowMs);
  const late = run(start + windowMs + 30_000);
  assert.deepStrictEqual(onBoundary, late);
  assert.strictEqual(onBoundary.length, 1);
});

test('idle learning windows are stored and raise the volume threshold', () => {
  const windowMs = 60_000;
  const engine = createEngine({ learnMs: 180_000, windowMs, minBytes: 0, sigma: 4, peakFactor: 2 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1_000_000, ts: 0 });
  engine.flush(120_000);
  const samples = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['volume-spike'].state
    .samples;
  assert.ok(samples.includes(0));
  assert.ok(samples.includes(1_000_000));
  const bag = take(engine);
  engine.feed({ device: 'd', dst: 'a.example', bytes: 2_100_000, ts: 180_000 });
  engine.flush(240_000);
  assert.strictEqual(bag.anomalies.filter((item) => item.detector === 'volume-spike').length, 0);
  engine.feed({ device: 'd', dst: 'a.example', bytes: 5_000_000, ts: 240_000 });
  engine.flush(300_000);
  assert.ok(bag.anomalies.some((item) => item.detector === 'volume-spike'));
});

test('import rejects prototype pollution, oversize state, and windowMs mismatch without changing state', () => {
  const engine = createEngine({ learnMs: DAY, windowMs: 60_000 });
  engine.feed({ device: 'keep', dst: 'ok.example', bytes: 10, ts: T0 });
  const before = engine.exportBaseline({ createdAt: 1 });

  const polluted = JSON.parse(JSON.stringify(before));
  Object.defineProperty(polluted.devices, '__proto__', {
    value: { pwned: true },
    enumerable: true,
  });
  assert.throws(() => engine.importBaseline(polluted), /forbidden key/);

  const fat = JSON.parse(JSON.stringify(before));
  fat.devices.keep.detectors['new-destination'].state.dsts = Array.from(
    { length: 5001 },
    (_, i) => `h${i}.example`,
  );
  assert.throws(() => engine.importBaseline(fat), /exceeds cap/);

  const long = JSON.parse(JSON.stringify(before));
  long.devices.keep.detectors['new-destination'].state.dsts = ['x'.repeat(256)];
  assert.throws(() => engine.importBaseline(long), /string too long/);

  const wrongWindow = JSON.parse(JSON.stringify(before));
  wrongWindow.engine.windowMs = 1000;
  assert.throws(() => engine.importBaseline(wrongWindow), /windowMs/);

  assert.deepStrictEqual(engine.exportBaseline({ createdAt: 1 }), before);
});

test('allow suppresses a later new-destination for that host', () => {
  const engine = createEngine({ learnMs: 1000, windowMs: 60_000 });
  const bag = take(engine);
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.lock('d');
  engine.allow('d', 'dst', 'evil.example');
  engine.feed({ device: 'd', dst: 'evil.example', bytes: 10, ts: 120_000 });
  assert.strictEqual(bag.anomalies.filter((item) => item.detector === 'new-destination').length, 0);
});

test('relearn emits nothing until learnMs passes, then emits learned', () => {
  const learnMs = 60_000;
  const engine = createEngine({ learnMs, windowMs: 60_000 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  const bag = take(engine);
  engine.relearn('d');
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 100 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 30_000 });
  assert.deepStrictEqual(bag.learned, []);
  assert.deepStrictEqual(bag.anomalies, []);
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 100 + learnMs });
  assert.strictEqual(bag.learned.length, 1);
  assert.strictEqual(bag.learned[0].device, 'd');
  assert.deepStrictEqual(bag.anomalies, []);
});

test('a throwing listener does not stop later events', () => {
  const engine = createEngine({ learnMs: 1000, windowMs: 60_000, minBytes: 1 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.lock('d');
  let saw = 0;
  engine.on('anomaly', () => {
    saw += 1;
    throw new Error('boom');
  });
  const bag = take(engine);
  assert.doesNotThrow(() =>
    engine.feed({ device: 'd', dst: 'new.example', bytes: 10, ts: 120_000 }),
  );
  assert.doesNotThrow(() =>
    engine.feed({ device: 'd', dst: 'other.example', bytes: 10, ts: 180_000 }),
  );
  assert.ok(saw >= 2);
  assert.ok(bag.warnings.some((item) => item.code === 'LISTENER_ERROR'));
});

test('custom dayOf fires wrong-time once per local day, not once per UTC day', () => {
  const dayOf = (ts) => Math.floor(ts / (2 * DAY));
  const hourOf = (ts) => new Date(ts).getUTCHours();
  const engine = createEngine({ learnMs: DAY, windowMs: 60_000, hourOf, dayOf });
  const bag = take(engine);
  engine.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 10 * DAY + 8 * H });
  engine.lock('d');
  engine.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 12 * DAY + 3 * H });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 13 * DAY + 3 * H });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 14 * DAY + 3 * H });
  const wrong = bag.anomalies.filter((item) => item.detector === 'wrong-time');
  assert.strictEqual(wrong.length, 2);
});

test('a realistic camera week does not raise volume-spike', () => {
  const events = simulate({ profile: 'camera', days: 14, seed: 3, startTs: T0 });
  const engine = createEngine({ learnMs: 7 * DAY });
  const bag = take(engine);
  for (const event of events) engine.feed(event);
  engine.flush(T0 + 14 * DAY);
  assert.deepStrictEqual(
    bag.anomalies.filter((item) => item.detector === 'volume-spike'),
    [],
  );
});

test('version 1 baselines upgrade and keep new-destination', () => {
  const engine = createEngine({ windowMs: 60_000 });
  engine.importBaseline({
    version: 1,
    devices: {
      'cam-1': {
        dsts: ['video.vendor.com'],
        hours: [8, 9, 10],
        winBytes: [2000],
        winFanout: [1],
      },
    },
  });
  const bag = take(engine);
  engine.feed({ device: 'cam-1', dst: 'evil.example', bytes: 10, ts: T0 + 10 * H });
  assert.ok(
    bag.anomalies.some(
      (item) => item.detector === 'new-destination' && item.actual === 'evil.example',
    ),
  );
});

test('signed baselines reject tampering', () => {
  const engine = createEngine({ learnMs: DAY });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: T0 });
  const signed = engine.exportBaseline({ createdAt: 5, sign: 'test-key' });
  const other = createEngine({ learnMs: DAY });
  assert.doesNotThrow(() => other.importBaseline(signed, { verify: 'test-key' }));
  const tampered = JSON.parse(JSON.stringify(signed));
  tampered.devices.d.detectors['new-destination'].state.dsts.push('extra.example');
  assert.throws(() => other.importBaseline(tampered, { verify: 'test-key' }), /signature/);
});
