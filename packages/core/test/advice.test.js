'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { createEngine, detectors } = require('../src/index.js');

const FILE = path.join(__dirname, '../src/data/advice.json');
const MAX_FILE = 40 * 1024;
const MAX_STRING = 200;
const RATE = /\d+\s*%|false-positive|detection rate|per device-day/i;

test('every live detector has advice inside the caps', () => {
  const text = fs.readFileSync(FILE, 'utf8');
  assert.ok(Buffer.byteLength(text) <= MAX_FILE);
  const advice = JSON.parse(text);
  for (const det of Object.values(detectors)) {
    const shadow = det.meta && det.meta.mode === 'shadow';
    const row = advice[det.id];
    if (shadow) {
      assert.strictEqual(row, undefined, det.id);
      continue;
    }
    assert.ok(row, det.id);
    assert.ok(row.check.length >= 1 && row.check.length <= 3, det.id);
    assert.ok(row.benignCauses.length >= 1 && row.benignCauses.length <= 3, det.id);
    for (const item of [row.meaning, ...row.check, ...row.benignCauses]) {
      assert.strictEqual(typeof item, 'string', det.id);
      assert.ok(item.length > 0 && item.length <= MAX_STRING, det.id);
      assert.strictEqual(RATE.test(item), false, `${det.id} ${item}`);
    }
  }
});

test('explain returns the advice for the detector that fired', () => {
  const engine = createEngine({ learnMs: 0 });
  /** @type {any[]} */
  const hits = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'new-destination') hits.push(item);
  });
  engine.feed({ device: 'd', dst: 'new.example', bytes: 10, ts: 1000 });
  assert.ok(hits[0]);
  const row = engine.explain(hits[0].id);
  assert.strictEqual(row.advice.meaning.includes('destination'), true);
  assert.ok(row.advice.check.length >= 1);
  assert.strictEqual(
    row.advice.meaning,
    JSON.parse(fs.readFileSync(FILE, 'utf8'))['new-destination'].meaning,
  );
});
