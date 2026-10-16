'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

function heapUsed() {
  if (typeof global.gc !== 'function') throw new Error('run node with --expose-gc');
  global.gc();
  global.gc();
  return process.memoryUsage().heapUsed;
}

test('one million distinct destinations stay under 20 MB', () => {
  const engine = createEngine({
    learnMs: 10 * 24 * 3600e3,
    windowMs: 60_000,
    maxDestinations: 5000,
    maxWindowDestinations: 5000,
  });
  const before = heapUsed();
  for (let i = 0; i < 1_000_000; i++) {
    engine.feed({ device: 'mem', dst: `h${i}.example`, bytes: 1, ts: 1_000 + i });
  }
  const after = heapUsed();
  assert.ok(after - before < 20 * 1024 * 1024, `heap grew by ${after - before} bytes`);
});
