'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const WARM = 1_000;
const SAMPLES = 10_000;

const engine = createEngine({ learnMs: 0, tiers: TIERS });
for (let i = 0; i < WARM; i++) {
  engine.feed({ device: `d${i % 100}`, dst: 'warm.example', bytes: 100, ts: i * 1_000 });
}
/** @type {number[]} */
const samples = [];
for (let i = 0; i < SAMPLES; i++) {
  const ts = (WARM + i) * 1_000;
  const start = process.hrtime.bigint();
  engine.feed({ device: `d${i % 100}`, dst: 'bench.example', bytes: 100, ts });
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
  console.log('bench: over the x86 budget; recorded, not tuned');
}
