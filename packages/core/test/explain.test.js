'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const DAY = 24 * 60 * 60 * 1000;

test('a hard-rule explanation offers suppress for at most a day and no allow', () => {
  const engine = createEngine({ learnMs: 86_400_000 });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 100_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 0 });
  const jump = anomalies.find((item) => item.detector === 'clock-jump');
  assert.ok(jump);
  const explained = engine.explain(jump.id);
  assert.ok(explained);
  assert.strictEqual(explained.test, 'changed');
  assert.ok(explained.observed != null);
  assert.ok(explained.suppressWith.every((entry) => entry.method !== 'allow'));
  const suppress = explained.suppressWith[0];
  assert.strictEqual(suppress.method, 'suppress');
  assert.ok(suppress.args[2].untilTs <= jump.ts + DAY);
  assert.strictEqual(engine.explain('missing'), null);
});

test('explainCap drops the oldest id', () => {
  const engine = createEngine({ learnMs: 0, explainCap: 1 });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 60_000 });
  assert.ok(anomalies.length > 1);
  assert.strictEqual(engine.explain(anomalies[0].id), null);
  assert.ok(engine.explain(anomalies[anomalies.length - 1].id));
});
