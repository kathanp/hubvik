'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const { detectors } = require('../../src/index.js');

const ROWS = [
  ['beacon-change', 'learned'],
  ['answer-drift', 'answers'],
  ['ot-spoof', 'owners'],
  ['ot-value-out-of-range', 'ranges'],
];

test('oversize detector imports throw and leave the previous state', () => {
  for (const [id, field] of ROWS) {
    const det = detectors[id];
    const dev = det.createState();
    const before = det.exportState(dev);
    const state = { [field]: Array.from({ length: 5001 }, (_, i) => [String(i), { n: 1 }]) };
    assert.throws(() => det.importState(dev, state), /exceeds cap/, id);
    assert.deepStrictEqual(det.exportState(dev), before);
  }
});

test('detector-lint accepts the tree', () => {
  const out = execFileSync(process.execPath, ['scripts/detector-lint.mjs'], { encoding: 'utf8' });
  assert.match(out, /detector-lint: ok/);
});
