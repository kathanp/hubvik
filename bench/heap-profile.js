'use strict';

const { spawn } = require('node:child_process');
const { detectors } = require('../packages/core/src/index.js');

const node = process.execPath;
// Parallel workers share the machine and move the smaller deltas by several KB.
// The table in docs/BENCHMARKS.md was measured with one run at a time.
const workers = Number(process.env.WORKERS || 1);
const devices = process.env.DEVICES || '16';

/**
 * @param {NodeJS.ProcessEnv} env
 * @returns {Promise<{ disable: string | null, devices: number, events: number, heapBytes: number, kb: number }>}
 */
function run(env) {
  return new Promise((resolve, reject) => {
    const child = spawn(node, ['--expose-gc', 'bench/heap-one.js'], {
      env: { ...process.env, DEVICES: devices, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += chunk;
    });
    child.stderr.on('data', (chunk) => {
      err += chunk;
    });
    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(err || out || `exit ${code}`));
        return;
      }
      resolve(JSON.parse(out));
    });
  });
}

/**
 * @param {Array<() => Promise<any>>} jobs
 * @param {number} limit
 * @returns {Promise<any[]>}
 */
async function pool(jobs, limit) {
  /** @type {any[]} */
  const results = new Array(jobs.length);
  let next = 0;
  async function worker() {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= jobs.length) return;
      results[index] = await jobs[index]();
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, jobs.length) }, () => worker()));
  return results;
}

/**
 * Heap per device with one detector disabled at a time, against a repeated baseline.
 * @returns {Promise<void>}
 */
async function main() {
  const baselines = await pool([() => run({}), () => run({}), () => run({})], 1);
  baselines.sort((a, b) => a.kb - b.kb);
  const baseline = baselines[1];
  const ids = Object.keys(detectors);
  const jobs = ids.map((id) => () => run({ DISABLE: id }));
  jobs.push(() => run({ DISABLE_ALL: '1' }));
  const rows = await pool(jobs, workers);
  const off = rows[rows.length - 1];
  const deltas = rows.slice(0, -1).map((row) => ({
    id: row.disable,
    kb: baseline.kb - row.kb,
  }));
  deltas.sort((a, b) => b.kb - a.kb);
  process.stdout.write(
    `${JSON.stringify({ baseline, baselines: baselines.map((row) => row.kb), off, deltas }, null, 2)}\n`,
  );
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
