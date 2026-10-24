'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');
const invest = require('../../src/engine/stats/alphainvest');

/**
 * @returns {Record<string, { enabled: boolean }>}
 */
function onlyNewDestination() {
  /** @type {Record<string, { enabled: boolean }>} */
  const options = {};
  for (const id of Object.keys(detectors)) {
    if (id !== 'new-destination') options[id] = { enabled: false };
  }
  return options;
}

/**
 * @param {boolean} fdr
 * @param {boolean} alerts
 */
function engine(fdr, alerts) {
  return createEngine({
    learnMs: 0,
    fdr,
    alerts,
    detectors: onlyNewDestination(),
  });
}

/**
 * @param {import('../../src/index.js').Engine} target
 * @param {number[]} times
 * @returns {any[]}
 */
function feedNew(target, times) {
  /** @type {any[]} */
  const anomalies = [];
  target.on('anomaly', (row) => anomalies.push(row));
  times.forEach((ts, index) => {
    target.feed({ device: 'cam', dst: `host-${ts}-${index}.example`, bytes: 100, ts });
  });
  return anomalies;
}

test('alpha-investing discovers the first medium and defers the next two', () => {
  const book = invest.createBook();
  const first = invest.push(book, { id: '1', severity: 'medium', ts: 1000 });
  const second = invest.push(book, { id: '2', severity: 'medium', ts: 2000 });
  const third = invest.push(book, { id: '3', severity: 'medium', ts: 3000 });
  assert.deepStrictEqual([first, second, third], ['discover', 'defer', 'defer']);
  assert.strictEqual(book.wealth, 23);
  const high = invest.push(book, { id: '4', severity: 'high', ts: 4000 });
  assert.strictEqual(high, 'defer');
  const fresh = invest.createBook();
  assert.strictEqual(invest.push(fresh, { id: 'h', severity: 'high', ts: 1000 }), 'discover');
  const bypass = invest.push(book, { id: '5', severity: 'critical', hardRule: true, ts: 5000 });
  assert.strictEqual(bypass, 'bypass');
  const nextDay = invest.push(book, { id: '6', severity: 'medium', ts: 86400000 + 1000 });
  assert.strictEqual(nextDay, 'discover');
  assert.strictEqual(book.decisions.length, 1);
});

test('alpha-investing drops the oldest decision at the cap and rejects a bad book', () => {
  const book = invest.createBook();
  for (let i = 0; i < invest.CAP + 5; i += 1) {
    invest.push(book, { id: `n${i}`, severity: 'low', ts: 1000 + i });
  }
  assert.strictEqual(book.decisions.length, invest.CAP);
  assert.strictEqual(book.decisions[0].id, 'n5');
  const copy = invest.fromJSON(invest.toJSON(book));
  assert.deepStrictEqual(copy, { wealth: book.wealth, day: book.day, decisions: book.decisions });
  assert.throws(
    () => invest.fromJSON(null),
    (err) => err.code === 'CHECKPOINT_FDR_IS_INVALID',
  );
  assert.throws(
    () => invest.fromJSON({ wealth: 100, day: 0, decisions: [], constructor: 1 }),
    (err) => err.code === 'FORBIDDEN_KEY_AT',
  );
});

test('fdr off leaves anomalies unchanged and fdr on labels then holds the alert', () => {
  const times = [1000, 2000, 3000, 61000];
  const plain = engine(false, true);
  const held = engine(true, true);
  /** @type {any[]} */
  const alerts = [];
  /** @type {any[]} */
  const plainAlerts = [];
  plain.on('alert', (row) => plainAlerts.push(row));
  held.on('alert', (row) => alerts.push(row));
  const plainRows = feedNew(plain, times);
  const heldRows = feedNew(held, times);
  assert.ok(plainRows.length >= 4);
  assert.strictEqual(
    plainRows.some((row) => Object.hasOwn(row.data, 'fdr')),
    false,
  );
  assert.deepStrictEqual(
    heldRows.slice(0, 4).map((row) => row.data.fdr),
    ['discover', 'defer', 'defer', 'defer'],
  );
  assert.ok(plainAlerts.length >= 1);
  assert.strictEqual(alerts.length, 0);
  assert.throws(
    () => createEngine({ fdr: 'yes' }),
    (err) => err.code === 'MUST_BE_A_BOOLEAN',
  );
});

test('checkpoint keeps fdr wealth so the next medium stays deferred', () => {
  const first = engine(true, false);
  const opened = feedNew(first, [1000]);
  assert.strictEqual(opened[0].data.fdr, 'discover');
  const saved = first.checkpoint({ createdAt: 1 });
  assert.ok(saved.fdr);
  const restored = engine(true, false);
  restored.restore(saved);
  const again = feedNew(restored, [2000]);
  assert.strictEqual(again[0].data.fdr, 'defer');
  const fresh = engine(true, false);
  assert.strictEqual(feedNew(fresh, [2000])[0].data.fdr, 'discover');
});
