'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const DEVICES = 1_000;
const LEARN_MS = 60_000;
const SAMPLES = 10_000;

/**
 * Bytes the engine is actually holding: the V8 heap plus ArrayBuffer storage.
 * Float64Array rings live in `arrayBuffers`, which `heapUsed` does not include.
 * @returns {number}
 */
function heapUsed() {
  if (typeof global.gc !== 'function') throw new Error('bench needs node --expose-gc');
  global.gc();
  const usage = process.memoryUsage();
  return usage.heapUsed + usage.arrayBuffers;
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
  `bench median ${median.toFixed(2)} µs, estimate ${estimateKb.toFixed(2)} KB/device, retained ${heapKb.toFixed(2)} KB/device, devices ${stats.devices}`,
);
if (median >= 10 || heapKb >= 100) {
  console.error('bench: over the x86 budget');
  process.exit(1);
}

richBench();

/**
 * 200 devices, 7 days of rich class traffic, then lock.
 * Heap budget is 100 KB per device. The median is reported and is not a budget.
 * @returns {void}
 */
function richBench() {
  const { simulate } = require('../test/fixtures/sim');
  const { CLASS_NAMES } = require('../test/fixtures/profiles');
  const richDevices = 200;
  const rich = createEngine({ learnMs: 1e14, tiers: TIERS });
  const richBefore = heapUsed();
  let lastTs = 0;
  let events = 0;
  for (let i = 0; i < richDevices; i++) {
    const profile = CLASS_NAMES[i % CLASS_NAMES.length];
    const id = `rich-${i}`;
    rich.setDeviceClass(id, profile);
    const batch = simulate({ profile, days: 7, seed: i + 1, startTs: 0, rich: true });
    for (const event of batch) {
      const ts = event.ts;
      if (ts > lastTs) lastTs = ts;
      rich.feed({ ...event, device: id });
      events += 1;
    }
  }
  rich.lock();
  const richHeap = heapUsed() - richBefore;
  /** @type {number[]} */
  const richSamples = [];
  const richCount = 2_000;
  for (let i = 0; i < richCount; i++) {
    const ts = lastTs + 1_000 + i;
    const start = process.hrtime.bigint();
    rich.feed({
      device: `rich-${i % richDevices}`,
      dst: 'bench.example',
      bytes: 100,
      ts,
    });
    richSamples.push(Number(process.hrtime.bigint() - start) / 1_000);
  }
  richSamples.sort((a, b) => a - b);
  const richMedian = richSamples[Math.floor(richSamples.length / 2)];
  const richStats = rich.stats();
  const richHeapKb = richStats.devices > 0 ? richHeap / richStats.devices / 1024 : 0;
  console.log(
    `rich bench median ${richMedian.toFixed(2)} µs, retained ${richHeapKb.toFixed(2)} KB/device, devices ${richStats.devices}, events ${events}`,
  );
  if (richHeapKb >= 100) {
    console.error(`rich bench: retained ${richHeapKb.toFixed(2)} KB/device is over 100 KB`);
    process.exit(1);
  }
}
