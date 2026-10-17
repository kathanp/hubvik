'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const DEVICES = 1_000;
const LEARN_MS = 60_000;
const SAMPLES = 10_000;

/**
 * Heap after a forced collection.
 * @returns {number}
 */
function heapUsed() {
  if (typeof global.gc !== 'function') throw new Error('bench needs node --expose-gc');
  global.gc();
  return process.memoryUsage().heapUsed;
}

const engine = createEngine({ learnMs: LEARN_MS, tiers: TIERS });
const before = heapUsed();
for (let i = 0; i < DEVICES; i++) {
  engine.feed({ device: `d${i}`, dst: 'learn.example', bytes: 100, ts: 0 });
  engine.feed({ device: `d${i}`, dst: 'learn.example', bytes: 100, ts: LEARN_MS });
}
engine.lock();
const heapBytes = heapUsed() - before;

/** @type {number[]} */
const samples = [];
for (let i = 0; i < SAMPLES; i++) {
  const ts = LEARN_MS + 1_000 + i;
  const start = process.hrtime.bigint();
  engine.feed({
    device: `d${i % DEVICES}`,
    dst: 'bench.example',
    bytes: 100,
    ts,
  });
  samples.push(Number(process.hrtime.bigint() - start) / 1_000);
}
samples.sort((a, b) => a - b);
const median = samples[Math.floor(samples.length / 2)];
const stats = engine.stats();
const estimateKb = stats.devices > 0 ? stats.memoryBytes / stats.devices / 1024 : 0;
const heapKb = stats.devices > 0 ? heapBytes / stats.devices / 1024 : 0;
console.log(
  `bench median ${median.toFixed(2)} µs, estimate ${estimateKb.toFixed(2)} KB/device, heap ${heapKb.toFixed(2)} KB/device, devices ${stats.devices}`,
);
if (median >= 10 || heapKb >= 100) {
  console.error('bench: over the x86 budget');
  process.exit(1);
}
