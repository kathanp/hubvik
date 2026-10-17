'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const DEVICES = 1_000;
const LEARN_MS = 60_000;
const SAMPLES = 10_000;

const engine = createEngine({ learnMs: LEARN_MS, tiers: TIERS });
for (let i = 0; i < DEVICES; i++) {
  engine.feed({ device: `d${i}`, dst: 'learn.example', bytes: 100, ts: 0 });
  engine.feed({ device: `d${i}`, dst: 'learn.example', bytes: 100, ts: LEARN_MS });
}
engine.lock();

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
const perDevice = stats.devices > 0 ? stats.memoryBytes / stats.devices : 0;
const kb = perDevice / 1024;
console.log(
  `bench median ${median.toFixed(2)} µs, ${kb.toFixed(2)} KB/device, devices ${stats.devices}`,
);
if (median >= 10 || kb >= 100) {
  console.error('bench: over the x86 budget');
  process.exit(1);
}
