'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const DAY = 24 * 60 * 60 * 1000;

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'cam-1',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    dstName: 'video.vendor.com',
    ...extra,
  };
}

test('twenty labels round-trip and a noisy detector warns once', () => {
  const engine = createEngine({ learnMs: 1000, tiers: ['T0'] });
  /** @type {any[]} */
  const found = [];
  /** @type {any[]} */
  const warnings = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'new-device') found.push(item);
  });
  engine.on('warning', (warning) => warnings.push(warning));
  engine.feed({ device: 'seed', dst: 'a.example', bytes: 1, ts: 0 });
  for (let i = 0; i < 20; i += 1) {
    engine.feed({ device: `d${i}`, dst: 'a.example', bytes: 1, ts: 5000 });
  }
  assert.strictEqual(found.length, 20);
  for (let i = 0; i < 20; i += 1) {
    const verdict = i < 11 ? 'fp' : i < 16 ? 'tp' : i < 18 ? 'benign-true' : 'unknown';
    engine.feedback(i % 2 === 0 ? found[i].id : found[i].fingerprint, verdict, {
      operator: 'ada',
      note: 'pilot',
    });
  }
  const text = engine.exportLabels();
  const rows = text
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line));
  assert.strictEqual(rows.length, 20);
  assert.strictEqual(rows[0].detector, 'new-device');
  assert.strictEqual(rows[0].device, 'd0');
  assert.strictEqual(rows[0].verdict, 'fp');
  assert.strictEqual(rows[0].operator, 'ada');
  assert.strictEqual(rows[0].fingerprint, found[0].fingerprint);
  const precision = engine.stats().precision['new-device'];
  assert.strictEqual(precision.fp, 11);
  assert.strictEqual(precision.tp, 5);
  assert.strictEqual(precision.benign, 2);
  assert.strictEqual(precision.unknown, 2);
  assert.ok(precision.fpRate > 0.5);
  assert.ok(precision.interval.low >= 0 && precision.interval.high <= 1);
  const noisy = warnings.filter((warning) => warning.code === 'NOISY_DETECTOR');
  assert.strictEqual(noisy.length, 1);
  assert.strictEqual(noisy[0].detector, 'new-device');

  const saved = engine.checkpoint({ createdAt: 1 });
  const restored = createEngine({ learnMs: 1000, tiers: ['T0'] });
  restored.restore(saved);
  assert.strictEqual(restored.exportLabels(), text);
  assert.strictEqual(restored.stats().precision['new-device'].fp, 11);

  const over = engine.checkpoint({ createdAt: 1 });
  over.feedback = Array.from({ length: 10001 }, () => over.feedback[0]);
  assert.throws(() => restored.restore(over), /exceeds cap/);
  assert.throws(() => engine.feedback('missing', 'tp'), /unknown anomaly/);
  assert.throws(() => engine.feedback(found[0].id, 'maybe'), /verdict is invalid/);
});

test('a watched family is promoted after 3 days and 10 hits', () => {
  const engine = createEngine({
    learnMs: 30 * DAY,
    tiers: ['T0', 'T1'],
    promote: { afterDays: 3, minHits: 10 },
  });
  /** @type {any[]} */
  const warnings = [];
  /** @type {any[]} */
  const families = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.on('anomaly', (item) => {
    if (item.detector === 'new-domain-family') families.push(item.actual);
  });
  engine.feed(flow({ ts: 0, dstName: 'known.example.com' }));
  engine.lock('cam-1');
  const hits = [
    [1, 4],
    [2, 3],
    [3, 3],
  ];
  for (const [day, count] of hits) {
    for (let i = 0; i < count; i += 1) {
      engine.feed(flow({ ts: day * DAY + i * 1000, dstName: 'cdn.vendor.test' }));
    }
  }
  const promoted = warnings.filter((warning) => warning.code === 'BASELINE_PROMOTED');
  assert.strictEqual(promoted.length, 1);
  assert.strictEqual(promoted[0].detector, 'new-domain-family');
  assert.strictEqual(promoted[0].value, 'vendor.test');
  assert.strictEqual(promoted[0].device, 'cam-1');
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = saved.devices['cam-1'].detectors['new-domain-family'].state.families;
  assert.ok(learned.includes('vendor.test'));
  const before = families.length;
  engine.feed(flow({ ts: 4 * DAY, dstName: 'cdn.vendor.test' }));
  assert.strictEqual(families.length, before);
});

test('a high anomaly in the same period blocks promotion', () => {
  const engine = createEngine({
    learnMs: 30 * DAY,
    tiers: ['T0', 'T1'],
    promote: { afterDays: 3, minHits: 10 },
    detectors: { 'new-domain-family': { severity: 'high' } },
  });
  /** @type {string[]} */
  const codes = [];
  engine.on('warning', (warning) => codes.push(warning.code));
  engine.feed(flow({ ts: 0, dstName: 'known.example.com' }));
  engine.lock('cam-1');
  for (const day of [1, 2, 3]) {
    for (let i = 0; i < 4; i += 1) {
      engine.feed(flow({ ts: day * DAY + i * 1000, dstName: 'cdn.vendor.test' }));
    }
  }
  assert.ok(!codes.includes('BASELINE_PROMOTED'));
});

test('the candidate cap drops the oldest family before it can be promoted', () => {
  const engine = createEngine({
    learnMs: 30 * DAY,
    tiers: ['T0', 'T1'],
    promote: { afterDays: 1, minHits: 10 },
  });
  /** @type {string[]} */
  const codes = [];
  engine.on('warning', (warning) => codes.push(warning.code));
  engine.feed(flow({ ts: 0, dstName: 'known.example.com' }));
  engine.lock('cam-1');
  for (let i = 0; i < 9; i += 1) {
    engine.feed(flow({ ts: DAY + i * 1000, dstName: 'keep.example' }));
  }
  for (let i = 0; i < 500; i += 1) {
    engine.feed(flow({ ts: DAY + 20_000 + i, dstName: `b${i}.example`, dstIp: '9.9.9.9' }));
  }
  engine.feed(flow({ ts: DAY + 30_000, dstName: 'keep.example' }));
  assert.ok(!codes.includes('BASELINE_PROMOTED'));
});

test('promotion stays off unless the host asks for it', () => {
  const engine = createEngine({ learnMs: 30 * DAY, tiers: ['T0', 'T1'] });
  /** @type {string[]} */
  const codes = [];
  engine.on('warning', (warning) => codes.push(warning.code));
  engine.feed(flow({ ts: 0, dstName: 'known.example.com' }));
  engine.lock('cam-1');
  for (const day of [1, 2, 3]) {
    for (let i = 0; i < 4; i += 1) {
      engine.feed(flow({ ts: day * DAY + i * 1000, dstName: 'cdn.vendor.test' }));
    }
  }
  assert.ok(!codes.includes('BASELINE_PROMOTED'));
  assert.throws(() => createEngine({ promote: true }), /promote must be false or an object/);
});
