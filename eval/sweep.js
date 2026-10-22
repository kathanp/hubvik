'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { detectors } = require('hubvik');
const { loadIot23 } = require('./iot23.js');
const { loadCiciot2023 } = require('./ciciot2023.js');
const { loadIeeeDataport } = require('./ieee-dataport.js');
const { loadCiciomt2024 } = require('./ciciomt2024.js');
const { operatingPoint } = require('./protocol.js');
const { loadCached } = require('./cache.js');

const MAX_POINTS = 50;
const BLOCKED = new Set(['evasion', 'evasion-holdout', 'adversary']);

/**
 * Sweeps never run on the evasion or adversary trees. Those suites measure blind spots.
 * @param {string} zeekLogs
 * @returns {void}
 */
function assertSweepPath(zeekLogs) {
  const resolved = path.resolve(zeekLogs);
  const rel = path.relative(path.resolve(__dirname), resolved);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return;
  const top = rel.split(path.sep)[0];
  if (BLOCKED.has(top)) {
    throw new Error('sweeps never run on eval/evasion, eval/evasion-holdout, or eval/adversary');
  }
}

/**
 * `<detector>.<param>=<from>:<to>:<step>`. At most 50 points.
 * @param {string} text
 * @returns {{ detector: string, param: string, from: number, to: number, step: number, points: number[] }}
 */
function parseSweep(text) {
  const match =
    /^([a-z0-9-]+)\.([A-Za-z][A-Za-z0-9]*)=(-?\d+(?:\.\d+)?):(-?\d+(?:\.\d+)?):(-?\d+(?:\.\d+)?)$/.exec(
      text || '',
    );
  if (!match) throw new TypeError('sweep must be <detector>.<param>=<from>:<to>:<step>');
  const detector = match[1];
  const param = match[2];
  const from = Number(match[3]);
  const to = Number(match[4]);
  const step = Number(match[5]);
  if (!(step > 0) || !(to >= from) || !Number.isFinite(from) || !Number.isFinite(to)) {
    throw new TypeError('sweep range is invalid');
  }
  if (!detectors[detector]) throw new TypeError(`unknown detector ${detector}`);
  const count = Math.floor((to - from) / step + 1e-9) + 1;
  if (count > MAX_POINTS) throw new TypeError('sweep has more than 50 points');
  /** @type {number[]} */
  const points = [];
  for (let i = 0; i < count; i += 1) {
    const value = Math.round((from + i * step) * 1e9) / 1e9;
    if (value > to + 1e-9) break;
    points.push(value);
  }
  if (points.length === 0 || points.length > MAX_POINTS) {
    throw new TypeError('sweep has more than 50 points');
  }
  return { detector, param, from, to, step, points };
}

/**
 * `--cost fp=<weight>,miss=<weight>`. Weights are the operator's choice.
 * @param {string | undefined} text
 * @returns {{ fp: number, miss: number } | null}
 */
function parseCost(text) {
  if (text == null) return null;
  const match = /^fp=(-?\d+(?:\.\d+)?),miss=(-?\d+(?:\.\d+)?)$/.exec(text);
  if (!match) throw new TypeError('cost must be fp=<weight>,miss=<weight>');
  const fp = Number(match[1]);
  const miss = Number(match[2]);
  if (!(fp >= 0) || !(miss >= 0) || !Number.isFinite(fp) || !Number.isFinite(miss)) {
    throw new TypeError('cost weights must be non-negative numbers');
  }
  return { fp, miss };
}

/**
 * Same joiners as `eval/cli.js`. Tiers stay with the dataset, not the sweep.
 * @param {string} dataset
 * @param {string} dir
 * @returns {{ rows: object[], tiers: string[] }}
 */
function loadJoined(dataset, dir) {
  if (dataset === 'iot23') return { rows: loadIot23(dir), tiers: ['T1'] };
  if (dataset === 'ciciot2023') return { rows: loadCiciot2023(dir), tiers: ['T1', 'T2', 'T3'] };
  if (dataset === 'ieee-dataport') return { rows: loadIeeeDataport(dir), tiers: ['T1', 'T4'] };
  if (dataset === 'ciciomt2024') return { rows: loadCiciomt2024(dir), tiers: ['T1', 'T2', 'T5'] };
  throw new TypeError(`no joiner for dataset ${dataset}`);
}

/**
 * Zeek logs when they were passed. Otherwise the synthetic IoT-23 fixture, labeled synthetic.
 * @param {{ dataset?: string, zeekLogs?: string }} args
 * @param {{ cacheDir?: string }} opts
 * @returns {{ rows: object[], tiers: string[], dataset: string }}
 */
function loadSweepDataset(args, opts) {
  const synthetic = !args.zeekLogs;
  if (!synthetic) assertSweepPath(args.zeekLogs);
  const dataset = synthetic ? 'synthetic' : args.dataset || 'iot23';
  const source = synthetic ? path.join(__dirname, 'fixtures') : args.zeekLogs;
  const joiner = synthetic ? 'iot23' : dataset;
  const cacheDir = opts.cacheDir || path.join(__dirname, '.cache');
  return loadCached(cacheDir, `${joiner}:${dataset}`, source, () => {
    const loaded = loadJoined(joiner, source);
    return { rows: loaded.rows, tiers: loaded.tiers, dataset };
  });
}

/**
 * False positives per device-day rise while the threshold rises.
 * @param {{ value: number, fpPerDeviceDay: number | null }[]} points
 * @returns {boolean}
 */
function fpRisesWithThreshold(points) {
  const sorted = points.slice().sort((a, b) => a.value - b.value);
  for (let i = 1; i < sorted.length; i += 1) {
    const prev = sorted[i - 1].fpPerDeviceDay;
    const next = sorted[i].fpPerDeviceDay;
    if (prev == null || next == null) continue;
    if (next > prev + 1e-12) return true;
  }
  return false;
}

/**
 * @param {number} value
 * @returns {string}
 */
function formatNum(value) {
  if (value == null || Number.isNaN(value)) return 'no rate';
  if (Number.isInteger(value)) return String(value);
  return value.toFixed(4);
}

/**
 * Lowest expected cost. Equal costs stay on the shipped default when that point was swept.
 * The number is a proposal. Nothing in `packages/core` is written.
 * @param {any[]} points
 * @param {{ fp: number, miss: number }} weights
 * @param {number | undefined} shipped
 * @returns {any}
 */
function lowestCost(points, weights, shipped) {
  /** @type {any} */
  let best = null;
  for (const point of points) {
    const missRate =
      point.attackInstances === 0
        ? 0
        : (point.attackInstances - point.detected) / point.attackInstances;
    const fpRate = point.fpPerDeviceDay == null ? 0 : point.fpPerDeviceDay;
    const expectedCost = weights.fp * fpRate + weights.miss * missRate;
    const candidate = { value: point.value, expectedCost };
    if (!best || expectedCost < best.expectedCost - 1e-12) {
      best = candidate;
      continue;
    }
    if (Math.abs(expectedCost - best.expectedCost) > 1e-12) continue;
    const shippedNum = typeof shipped === 'number' ? shipped : null;
    const bestDist = shippedNum == null ? Infinity : Math.abs(best.value - shippedNum);
    const dist = shippedNum == null ? Infinity : Math.abs(point.value - shippedNum);
    if (dist < bestDist || (dist === bestDist && point.value > best.value)) best = candidate;
  }
  return best;
}

/**
 * @param {any} report
 * @returns {string}
 */
function renderSweep(report) {
  const lines = [
    `# Sweep ${report.detector}.${report.param}`,
    '',
    `Dataset: ${report.dataset}. ${report.points.length} points. The default was not changed.`,
    '',
    '| value | detection | FP/device-day | precision | recall |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const point of report.points) {
    const fp =
      point.fpPerDeviceDay == null
        ? 'no rate'
        : `${formatNum(point.fpPerDeviceDay)} (${point.fpPerDeviceDayWilson})`;
    lines.push(
      `| ${point.value} | ${point.detection} | ${fp} | ${formatNum(point.precision)} | ${formatNum(point.recall)} |`,
    );
  }
  lines.push('');
  if (report.fpRisesWithThreshold) {
    lines.push('probable detector bug: false positives rise as the threshold rises', '');
  } else {
    lines.push('Monotonicity: false positives do not rise as the threshold rises.', '');
  }
  lines.push('## Proposal', '');
  if (!report.proposal) lines.push('None. Pass --cost fp=<weight>,miss=<weight> to write one.', '');
  else lines.push(report.proposal.text, '');
  return `${lines.join('\n')}\n`;
}

/**
 * Replay once per point and write `eval/results/sweep/<detector>-<param>.json` and `.md`.
 * @param {{ sweep: string, cost?: string, dataset?: string, zeekLogs?: string }} args
 * @param {{ outDir?: string, cacheDir?: string, quiet?: boolean }} [opts]
 * @returns {any}
 */
function runSweep(args, opts = {}) {
  const spec = parseSweep(args.sweep);
  const cost = parseCost(args.cost);
  const loaded = loadSweepDataset(args, opts);
  const points = spec.points.map((value) => {
    const measured = operatingPoint(loaded.rows, {
      tiers: loaded.tiers,
      detectors: { [spec.detector]: { [spec.param]: value } },
    });
    return { value, ...measured };
  });
  const rises = fpRisesWithThreshold(points);
  const defaults = detectors[spec.detector].defaults || {};
  const shipped = defaults[spec.param];
  /** @type {any} */
  let proposal = null;
  if (cost) {
    const best = lowestCost(points, cost, typeof shipped === 'number' ? shipped : undefined);
    const text =
      `Proposal: ${spec.detector}.${spec.param} = ${best.value}. ` +
      `Expected cost ${formatNum(best.expectedCost)} with fp=${cost.fp}, miss=${cost.miss}. ` +
      "The default is unchanged. Cost weights are the operator's choice.";
    proposal = {
      detector: spec.detector,
      param: spec.param,
      value: best.value,
      expectedCost: best.expectedCost,
      fp: cost.fp,
      miss: cost.miss,
      shippedDefault: shipped == null ? null : shipped,
      defaultUnchanged: true,
      text,
    };
  }
  const report = {
    dataset: loaded.dataset,
    detector: spec.detector,
    param: spec.param,
    from: spec.from,
    to: spec.to,
    step: spec.step,
    points,
    fpRisesWithThreshold: rises,
    flag: rises ? 'probable detector bug: false positives rise as the threshold rises' : null,
    proposal,
  };
  const dir = path.join(opts.outDir || path.join(__dirname, 'results'), 'sweep');
  fs.mkdirSync(dir, { recursive: true });
  const base = `${spec.detector}-${spec.param}`;
  fs.writeFileSync(path.join(dir, `${base}.json`), `${JSON.stringify(report, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, `${base}.md`), renderSweep(report));
  if (!opts.quiet) {
    console.log(`sweep: ${loaded.dataset} ${spec.detector}.${spec.param} ${points.length} points`);
    if (report.flag) console.log(report.flag);
    if (proposal) console.log(proposal.text);
  }
  return report;
}

module.exports = {
  parseSweep,
  parseCost,
  runSweep,
  loadSweepDataset,
  fpRisesWithThreshold,
  assertSweepPath,
};
