'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../packages/core/src/index.js');
const { capture } = require('./corpus');

test('families true does not raise incident or alert counts and drops no incident', () => {
  const off = run(false);
  const on = run(true);
  assert.deepStrictEqual(Object.keys(on), Object.keys(off));
  for (const key of Object.keys(off)) {
    const left = off[key];
    const right = on[key];
    assert.strictEqual(right.anomalies.length, left.anomalies.length, key);
    assert.ok(right.incidents <= left.incidents, `${key} incidents`);
    assert.ok(right.alerts <= left.alerts, `${key} alerts`);
    if (left.incidents > 0) assert.ok(right.incidents > 0, `${key} lost an incident`);
    for (let i = 0; i < left.anomalies.length; i++)
      sameAnomaly(left.anomalies[i], right.anomalies[i], key);
  }
});

/**
 * @param {boolean} families
 */
function run(families) {
  /** @type {{ incidents: number, alerts: number }[]} */
  const counts = [];
  const rows = capture((opts) => {
    const engine = createEngine({ ...opts, families, alerts: true });
    const row = { incidents: 0, alerts: 0 };
    engine.on('incident', () => {
      row.incidents += 1;
    });
    engine.on('alert', () => {
      row.alerts += 1;
    });
    counts.push(row);
    return engine;
  });
  const keys = Object.keys(rows);
  assert.strictEqual(keys.length, counts.length);
  /** @type {Record<string, { incidents: number, alerts: number, anomalies: any[] }>} */
  const out = Object.create(null);
  keys.forEach((key, index) => {
    out[key] = {
      incidents: counts[index].incidents,
      alerts: counts[index].alerts,
      anomalies: rows[key].anomalies,
    };
  });
  return out;
}

/**
 * @param {any} left
 * @param {any} right
 * @param {string} key
 */
function sameAnomaly(left, right, key) {
  assert.strictEqual(right.detector, left.detector, key);
  assert.strictEqual(right.device, left.device, key);
  assert.strictEqual(right.ts, left.ts, key);
  assert.strictEqual(right.severity, left.severity, key);
  const data = { ...right.data };
  delete data.family;
  assert.deepStrictEqual(data, left.data, key);
}
