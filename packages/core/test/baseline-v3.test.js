'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { statsFromValues } = require('../src/engine/math');
const golden = require('../../../test/diff/golden.json');

/**
 * @param {number} left
 * @param {number} right
 * @returns {boolean}
 */
function close(left, right) {
  const scale = Math.max(Math.abs(left), Math.abs(right));
  if (scale === 0) return left === right;
  return Math.abs(left - right) / scale <= 1e-9;
}

test('a v2 baseline from d4a742f upgrades sample rings to streaming stats', () => {
  const saved = golden['benign:camera:seed1'].baseline;
  assert.strictEqual(saved.version, 2);
  const engine = createEngine();
  engine.importBaseline(saved);
  const out = engine.exportBaseline({ createdAt: saved.createdAt });
  assert.strictEqual(out.version, 3);
  const device = 'camera-1';
  const before = saved.devices[device].detectors;
  const after = out.devices[device].detectors;
  for (const id of ['volume-spike', 'fan-out']) {
    const folded = statsFromValues(before[id].state.samples);
    assert.strictEqual(after[id].state.count, folded.count);
    assert.ok(close(after[id].state.mean, folded.mean));
    assert.ok(close(after[id].state.m2, folded.m2));
    assert.ok(close(after[id].state.max, folded.max));
  }
  const oldHours = before['volume-spike-hourly'].state.hours;
  const newHours = after['volume-spike-hourly'].state.hours;
  assert.strictEqual(newHours.length, 24);
  for (let hour = 0; hour < 24; hour++) {
    const folded = statsFromValues(oldHours[hour]);
    assert.strictEqual(newHours[hour].count, folded.count);
    assert.ok(close(newHours[hour].mean, folded.mean));
    assert.ok(close(newHours[hour].m2, folded.m2));
    assert.ok(close(newHours[hour].max, folded.max));
  }
});

test('a version 1 baseline still imports into streaming stats', () => {
  const engine = createEngine({ windowMs: 60_000 });
  engine.importBaseline({
    version: 1,
    devices: {
      d: { dsts: ['a.example'], hours: [8], winBytes: [2000], winFanout: [1] },
    },
  });
  const out = engine.exportBaseline({ createdAt: 0 });
  assert.strictEqual(out.version, 3);
  assert.deepStrictEqual(out.devices.d.detectors['volume-spike'].state, {
    count: 1,
    mean: 2000,
    m2: 0,
    max: 2000,
  });
  assert.deepStrictEqual(out.devices.d.detectors['fan-out'].state, {
    count: 1,
    mean: 1,
    m2: 0,
    max: 1,
  });
});
