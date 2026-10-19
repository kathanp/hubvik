'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const HOUR = 3600e3;

/**
 * @param {number} ts
 * @param {number} bytesOut
 * @param {string} [dstIp]
 */
function flow(ts, bytesOut, dstIp = '9.9.9.9') {
  return {
    type: 'flow',
    device: 'd',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp,
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut,
    bytesIn: 10,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 20,
  };
}

test('the hourly ring sums event time and a long gap clears it', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1'], horizons: true });
  engine.feed(flow(0, 100));
  engine.feed(flow(HOUR, 250));
  engine.flush(2 * HOUR);
  const saved = engine.checkpoint({ createdAt: 1 });
  const next = createEngine({ learnMs: 0, tiers: ['T1'], horizons: true });
  next.restore(saved);
  next.feed(flow(HOUR + 1000, 50));
  const view = next.checkpoint({ createdAt: 2 });
  const progress = view.devices.d.progress.horizon;
  assert.ok(progress);
  assert.ok(progress.rows.length >= 1);
  const bytes =
    progress.rows.reduce((sum, row) => sum + row.bytesOut, 0) +
    (progress.open ? progress.open.bytesOut : 0);
  assert.strictEqual(bytes, 400);

  const gap = createEngine({ learnMs: 0, tiers: ['T1'], horizons: true });
  /** @type {string[]} */
  const warnings = [];
  gap.on('warning', (warning) => warnings.push(warning.code));
  gap.feed(flow(0, 100));
  gap.feed(flow(25 * HOUR, 5));
  const after = gap.checkpoint({ createdAt: 3 }).devices.d.progress.horizon;
  const left =
    after.rows.reduce((sum, row) => sum + row.bytesOut, 0) + (after.open ? after.open.bytesOut : 0);
  assert.strictEqual(left, 5);
  assert.deepStrictEqual(warnings, []);
});

test('horizons stay off when T1 is off', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  const saved = engine.checkpoint({ createdAt: 1 });
  assert.strictEqual(saved.devices.d.progress.horizon, undefined);
});
