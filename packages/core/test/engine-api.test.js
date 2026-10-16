'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

test('unknown event type throws and does not create a device', () => {
  const engine = createEngine();
  assert.throws(() => engine.feed({ device: 'd', type: 'nope', ts: 1 }), /unknown event type/);
  assert.strictEqual(engine.stats().devices, 0);
});

test('malformed optional fields are dropped and counted', () => {
  const engine = createEngine({ learnMs: 0, windowMs: 60_000 });
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'd', dst: 12, bytes: -5, ts: 1000 });
  assert.ok(warnings.some((warning) => warning.code === 'FIELD_DROPPED'));
  assert.strictEqual(engine.stats().events, 1);
});

test('missing device throws', () => {
  const engine = createEngine();
  assert.throws(() => engine.feed({ bytes: 1, ts: 1 }), /device/);
});

test('feedBatch sorts by timestamp before a hard-rule detector sees events', () => {
  const engine = createEngine({ learnMs: DAY_MS() });
  const seen = [];
  engine.use({
    id: 'tap',
    version: 1,
    requires: ['T0'],
    defaults: {},
    hardRule: true,
    category: 'integrity',
    check(_dev, ev) {
      seen.push(ev.ts);
    },
  });
  engine.feedBatch([
    { device: 'd', dst: 'b.example', bytes: 1, ts: 500 },
    { device: 'd', dst: 'a.example', bytes: 1, ts: 100 },
  ]);
  assert.deepStrictEqual(seen, [100, 500]);
});

test('a detector that needs T1 stays inactive on a T0 engine', () => {
  const engine = createEngine();
  engine.use({
    id: 'needs-flow',
    version: 1,
    requires: ['T1'],
    defaults: {},
    category: 'scan',
  });
  const status = engine.stats().detectors['needs-flow'];
  assert.strictEqual(status.active, false);
  assert.match(status.reason, /T1/);
});

test('device cap stops tracking and warns', () => {
  const engine = createEngine({ maxDevices: 1, learnMs: 0 });
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'a', dst: 'a.example', bytes: 1, ts: 1 });
  engine.feed({ device: 'b', dst: 'b.example', bytes: 1, ts: 2 });
  assert.strictEqual(engine.stats().devices, 1);
  assert.ok(warnings.some((warning) => warning.code === 'STATE_CAP'));
});

test('destination cap stays bounded', () => {
  const engine = createEngine({ learnMs: DAY_MS(), maxDestinations: 3, windowMs: 60_000 });
  for (let i = 0; i < 10; i++)
    engine.feed({ device: 'd', dst: `h${i}.example`, bytes: 1, ts: i * 1000 });
  const dsts = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination'].state
    .dsts;
  assert.strictEqual(dsts.length, 3);
});

test('alert dedup cap stays bounded', () => {
  const engine = createEngine({
    learnMs: 1,
    maxAlertKeys: 2,
    maxNewDstPerWindow: 100,
    windowMs: 60_000,
  });
  engine.feed({ device: 'd', dst: 'seed.example', bytes: 1, ts: 0 });
  engine.lock('d');
  for (let i = 0; i < 6; i++) {
    engine.feed({ device: 'd', dst: `new-${i}.example`, bytes: 1, ts: 120_000 + i });
  }
  const alerted = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination']
    .state.alerted;
  assert.strictEqual(alerted.length, 2);
});

test('sample history cap stays bounded', () => {
  const engine = createEngine({ learnMs: 10_000_000, windowMs: 1000, maxWindows: 4 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.flush(20_000);
  const samples = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['volume-spike'].state
    .samples;
  assert.ok(samples.length <= 4);
  assert.ok(samples.length >= 1);
});

test('IPv4-mapped IPv6 is the same destination as the IPv4 host', () => {
  const engine = createEngine({ learnMs: 1000, windowMs: 60_000 });
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: '::ffff:10.1.2.3', bytes: 10, ts: 0 });
  engine.lock('d');
  engine.feed({ device: 'd', dst: '10.1.2.3', bytes: 10, ts: 120_000 });
  assert.strictEqual(anomalies.filter((item) => item.detector === 'new-destination').length, 0);
});

test('clock jump warns and does not move the open window backward', () => {
  const engine = createEngine({ learnMs: DAY_MS(), windowMs: 60_000 });
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 50, ts: 120_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 50, ts: 10_000 });
  assert.ok(warnings.some((warning) => warning.code === 'CLOCK_JUMP'));
  const dsts = engine.exportBaseline({ createdAt: 0 }).devices.d.detectors['new-destination'].state
    .dsts;
  assert.deepStrictEqual(dsts, ['a.example']);
});

test('loadIndicators replaces the set only after every item validates', () => {
  const engine = createEngine({ maxIndicators: 2 });
  engine.loadIndicators([{ value: '1.2.3.4', type: 'ip', source: 'lab', confidence: 1 }]);
  assert.throws(
    () =>
      engine.loadIndicators([{ value: 'not-a-cidr', type: 'cidr', source: 'lab', confidence: 1 }]),
    /cidr/,
  );
  assert.strictEqual(engine.stats().indicators, 1);
  assert.throws(
    () =>
      engine.loadIndicators([1, 2, 3].map(() => ({ value: '1.1.1.1', type: 'ip', source: 'lab' }))),
    /cap/,
  );
});

test('suppress mutes only the matching actual', () => {
  const engine = createEngine({ learnMs: 1000, windowMs: 60_000 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.lock('d');
  engine.suppress('d', 'new-destination', { match: 'evil.example' });
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'evil.example', bytes: 1, ts: 120_000 });
  engine.feed({ device: 'd', dst: 'other.example', bytes: 1, ts: 180_000 });
  const found = anomalies
    .filter((item) => item.detector === 'new-destination')
    .map((item) => item.actual);
  assert.deepStrictEqual(found, ['other.example']);
});

test('forget removes the device', () => {
  const engine = createEngine();
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 1 });
  engine.forget('d');
  assert.strictEqual(engine.stats().devices, 0);
});

test('anomaly ids are monotonic strings', () => {
  const engine = createEngine({ learnMs: 1000, windowMs: 60_000, maxNewDstPerWindow: 10 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.lock('d');
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'b.example', bytes: 1, ts: 120_000 });
  engine.feed({ device: 'd', dst: 'c.example', bytes: 1, ts: 180_000 });
  const ids = anomalies.map((item) => Number(item.id));
  assert.deepStrictEqual(ids, [1, 2]);
});

function DAY_MS() {
  return 24 * 3600e3;
}
