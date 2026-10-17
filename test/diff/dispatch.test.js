'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { createEngine } = require('../../packages/core/src/index.js');
const { capture } = require('./corpus');

const GOLDEN = path.join(__dirname, 'golden.json');

/**
 * @param {any} before
 * @param {any} after
 * @returns {string[]}
 */
function changedDetectors(before, after) {
  /** @type {Set<string>} */
  const ids = new Set();
  const left = before.anomalies || [];
  const right = after.anomalies || [];
  /**
   * @param {any} item
   */
  const key = (item) =>
    `${item.detector}\0${item.device}\0${item.ts}\0${item.severity}\0${JSON.stringify(item.data)}`;
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const item of left) counts.set(key(item), (counts.get(key(item)) || 0) + 1);
  for (const item of right) counts.set(key(item), (counts.get(key(item)) || 0) - 1);
  for (const [id, count] of counts) {
    if (count !== 0) ids.add(id.split('\0')[0]);
  }
  const devices = new Set([
    ...Object.keys((before.baseline && before.baseline.devices) || {}),
    ...Object.keys((after.baseline && after.baseline.devices) || {}),
  ]);
  for (const device of devices) {
    const a =
      before.baseline && before.baseline.devices[device]
        ? before.baseline.devices[device].detectors
        : {};
    const b =
      after.baseline && after.baseline.devices[device]
        ? after.baseline.devices[device].detectors
        : {};
    for (const id of new Set([...Object.keys(a || {}), ...Object.keys(b || {})])) {
      if (JSON.stringify(a[id]) !== JSON.stringify(b[id])) ids.add(id);
    }
  }
  return [...ids].sort();
}

test('dispatch matches the pre-dispatch anomaly stream and baseline', () => {
  const golden = JSON.parse(fs.readFileSync(GOLDEN, 'utf8'));
  const actual = capture(createEngine);
  const names = Object.keys(golden).sort();
  assert.deepStrictEqual(Object.keys(actual).sort(), names);
  /** @type {string[]} */
  const problems = [];
  for (const name of names) {
    if (JSON.stringify(golden[name]) === JSON.stringify(actual[name])) continue;
    const detectors = changedDetectors(golden[name], actual[name]);
    problems.push(`${name}: ${detectors.join(', ') || 'output shape'}`);
  }
  assert.deepStrictEqual(problems, []);
});
