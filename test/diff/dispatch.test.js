'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { createEngine } = require('../../packages/core/src/index.js');
const { statsFromValues } = require('../../packages/core/src/engine/math');
const { capture } = require('./corpus');

const GOLDEN = path.join(__dirname, 'golden.json');

const REL = 1e-9;
const NUMBER = /[+-]?(?:\d+\.\d+|\d+|\.\d+)(?:[eE][+-]?\d+)?/g;

/**
 * @param {number} left
 * @param {number} right
 * @returns {boolean}
 */
function closeNumber(left, right) {
  if (Object.is(left, right)) return true;
  if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
  const scale = Math.max(Math.abs(left), Math.abs(right));
  if (scale === 0) return true;
  return Math.abs(left - right) / scale <= REL;
}

/**
 * @param {string} left
 * @param {string} right
 * @returns {boolean}
 */
function closeString(left, right) {
  if (left === right) return true;
  const a = left.match(NUMBER) || [];
  const b = right.match(NUMBER) || [];
  if (a.length !== b.length) return false;
  if (left.replace(NUMBER, '#') !== right.replace(NUMBER, '#')) return false;
  for (let i = 0; i < a.length; i++) {
    if (!closeNumber(Number(a[i]), Number(b[i]))) return false;
  }
  return true;
}

/**
 * @param {any} left
 * @param {any} right
 * @returns {boolean}
 */
function closeValue(left, right) {
  if (typeof left === 'number' && typeof right === 'number') return closeNumber(left, right);
  if (typeof left === 'string' && typeof right === 'string') return closeString(left, right);
  if (Array.isArray(left) && Array.isArray(right)) {
    if (left.length !== right.length) return false;
    for (let i = 0; i < left.length; i++) {
      if (!closeValue(left[i], right[i])) return false;
    }
    return true;
  }
  if (left && right && typeof left === 'object' && typeof right === 'object') {
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    for (const key of keys) {
      if (!closeValue(left[key], right[key])) return false;
    }
    return true;
  }
  return Object.is(left, right);
}

/**
 * @param {any} state
 * @returns {{ count: number, mean: number, m2: number, max: number } | null}
 */
function asStats(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) return null;
  if (Array.isArray(state.samples)) return statsFromValues(state.samples);
  if (typeof state.count === 'number' && !Array.isArray(state.hours)) {
    return { count: state.count, mean: state.mean, m2: state.m2, max: state.max };
  }
  return null;
}

/**
 * @param {any} state
 * @returns {Array<{ count: number, mean: number, m2: number, max: number }> | null}
 */
function asHours(state) {
  if (!state || !Array.isArray(state.hours)) return null;
  return state.hours.map((hour) =>
    Array.isArray(hour)
      ? statsFromValues(hour)
      : { count: hour.count, mean: hour.mean, m2: hour.m2, max: hour.max },
  );
}

/**
 * @param {any} left
 * @param {any} right
 * @returns {boolean}
 */
function closeState(left, right) {
  const leftStats = asStats(left);
  const rightStats = asStats(right);
  if (leftStats && rightStats) return closeValue(leftStats, rightStats);
  const leftHours = asHours(left);
  const rightHours = asHours(right);
  if (leftHours && rightHours) return closeValue(leftHours, rightHours);
  return closeValue(left, right);
}

/**
 * @param {any} item
 * @returns {string}
 */
function anomalyKey(item) {
  return [item.detector, item.device, String(item.ts), item.severity, item.category || ''].join(
    '\0',
  );
}

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
  /** @type {Map<string, any[]>} */
  const groups = new Map();
  for (const item of left) {
    const key = anomalyKey(item);
    const list = groups.get(key) || [];
    list.push(item);
    groups.set(key, list);
  }
  for (const item of right) {
    const key = anomalyKey(item);
    const list = groups.get(key);
    if (!list || list.length === 0) {
      ids.add(item.detector);
      continue;
    }
    const index = list.findIndex(
      (other) =>
        (other.category || '') === (item.category || '') && closeValue(other.data, item.data),
    );
    if (index < 0) ids.add(item.detector);
    else list.splice(index, 1);
  }
  for (const list of groups.values()) {
    for (const item of list) ids.add(item.detector);
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
      const leftBlock = a[id];
      const rightBlock = b[id];
      if (!leftBlock || !rightBlock || leftBlock.v !== rightBlock.v) {
        ids.add(id);
        continue;
      }
      if (!closeState(leftBlock.state, rightBlock.state)) ids.add(id);
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
    if (
      golden[name].baseline.createdAt !== actual[name].baseline.createdAt ||
      !closeValue(golden[name].baseline.engine, actual[name].baseline.engine)
    ) {
      detectors.push('baseline-meta');
    }
    if (detectors.length > 0) problems.push(`${name}: ${detectors.join(', ')}`);
  }
  assert.deepStrictEqual(problems, []);
});
