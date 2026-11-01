'use strict';

const os = require('node:os');
const { createEngine } = require('../packages/core/src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const LEARN_MS = 60_000;
const DEVICES = 1_000;
const SAMPLES = 10_000;
const RICH_DEVICES = 200;
const RICH_SAMPLES = 2_000;
const RICH_DAYS = 7;
const BYTES = 100;

/**
 * @returns {number}
 */
function heapUsed() {
  if (typeof global.gc !== 'function') throw new Error('bench needs node --expose-gc');
  global.gc();
  const usage = process.memoryUsage();
  return usage.heapUsed + usage.arrayBuffers;
}

/**
 * @param {string} label
 * @param {number} median
 * @param {number} retainedKb
 * @param {number} devices
 * @returns {string}
 */
function benchLine(label, median, retainedKb, devices) {
  return `${label} median ${median.toFixed(2)} µs, retained ${retainedKb.toFixed(2)} KB/device, devices ${devices}`;
}

/**
 * @param {{ node: string, platform: string, arch: string, cpu: string, memory: string }} host
 * @param {string[]} lines
 * @returns {string}
 */
function formatBlock(host, lines) {
  const body = [
    '## Device bench',
    '',
    `node ${host.node}`,
    `platform ${host.platform}`,
    `arch ${host.arch}`,
    `cpu ${host.cpu}`,
    `memory ${host.memory}`,
    '',
    ...lines,
  ];
  if (host.arch !== 'arm' && host.arch !== 'arm64') {
    body.push('This is not a Raspberry Pi measurement.');
  }
  return body.join('\n');
}

/**
 * @param {Record<string, unknown>} extra
 * @returns {{ median: number, retainedKb: number, devices: number }}
 */
function watchBench(extra) {
  const engine = createEngine({ learnMs: LEARN_MS, tiers: TIERS, ...extra });
  const before = heapUsed();
  for (let i = 0; i < DEVICES; i++) {
    engine.feed({ device: `d${i}`, dst: 'learn.example', bytes: BYTES, ts: 0 });
    engine.feed({ device: `d${i}`, dst: 'learn.example', bytes: BYTES, ts: LEARN_MS });
  }
  engine.lock();
  const heap = heapUsed() - before;
  /** @type {number[]} */
  const samples = [];
  for (let i = 0; i < SAMPLES; i++) {
    const start = process.hrtime.bigint();
    engine.feed({
      device: `d${i % DEVICES}`,
      dst: 'bench.example',
      bytes: BYTES,
      ts: LEARN_MS + 1_000 + i,
    });
    samples.push(Number(process.hrtime.bigint() - start) / 1_000);
  }
  samples.sort((a, b) => a - b);
  const stats = engine.stats();
  const retainedKb = stats.devices > 0 ? heap / stats.devices / 1024 : 0;
  return { median: samples[Math.floor(samples.length / 2)], retainedKb, devices: stats.devices };
}

/**
 * @param {Record<string, unknown>} extra
 * @returns {{ median: number, retainedKb: number, devices: number }}
 */
function weekBench(extra) {
  const { simulate } = require('../test/fixtures/sim');
  const { CLASS_NAMES } = require('../test/fixtures/profiles');
  const neverLock = 1e14;
  const engine = createEngine({ learnMs: neverLock, tiers: TIERS, ...extra });
  const before = heapUsed();
  let lastTs = 0;
  for (let i = 0; i < RICH_DEVICES; i++) {
    const id = `rich-${i}`;
    const profile = CLASS_NAMES[i % CLASS_NAMES.length];
    engine.setDeviceClass(id, profile);
    const batch = simulate({ profile, days: RICH_DAYS, seed: i + 1, startTs: 0, rich: true });
    for (const event of batch) {
      if (event.ts > lastTs) lastTs = event.ts;
      engine.feed({ ...event, device: id });
    }
  }
  engine.lock();
  const heap = heapUsed() - before;
  /** @type {number[]} */
  const samples = [];
  for (let i = 0; i < RICH_SAMPLES; i++) {
    const start = process.hrtime.bigint();
    engine.feed({
      device: `rich-${i % RICH_DEVICES}`,
      dst: 'bench.example',
      bytes: BYTES,
      ts: lastTs + 1_000 + i,
    });
    samples.push(Number(process.hrtime.bigint() - start) / 1_000);
  }
  samples.sort((a, b) => a - b);
  const stats = engine.stats();
  const retainedKb = stats.devices > 0 ? heap / stats.devices / 1024 : 0;
  return { median: samples[Math.floor(samples.length / 2)], retainedKb, devices: stats.devices };
}

/**
 * A fresh process, so the retained-heap delta is not the previous bench being collected.
 * @returns {string}
 */
function coreLine() {
  const { spawnSync } = require('node:child_process');
  const result = spawnSync(process.execPath, ['--expose-gc', __filename, '--core-only'], {
    encoding: 'utf8',
  });
  if (result.status !== 0) throw new Error(result.stderr || 'core bench failed');
  return result.stdout.trim();
}

/**
 * @returns {void}
 */
function main() {
  if (process.argv.includes('--core-only')) {
    const core = watchBench({ profile: 'core' });
    console.log(benchLine('1,000-device profile core', core.median, core.retainedKb, core.devices));
    return;
  }
  const watching = watchBench({});
  const week = weekBench({});
  const shadow = weekBench({ shadow: true });
  const cpu = os.cpus()[0];
  const block = formatBlock(
    {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      cpu: cpu ? cpu.model : 'unknown',
      memory: `${os.totalmem()} bytes`,
    },
    [
      benchLine('1,000-device watching', watching.median, watching.retainedKb, watching.devices),
      benchLine('200-device 7-day', week.median, week.retainedKb, week.devices),
      benchLine('200-device 7-day shadow:true', shadow.median, shadow.retainedKb, shadow.devices),
    ],
  );
  console.log(block);
  console.log(coreLine());
}

if (require.main === module) main();

module.exports = { formatBlock, benchLine };
