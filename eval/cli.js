'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { loadIot23 } = require('./iot23.js');
const { loadCiciot2023 } = require('./ciciot2023.js');
const { loadIeeeDataport } = require('./ieee-dataport.js');
const { loadCiciomt2024 } = require('./ciciomt2024.js');
const {
  evaluate,
  renderMarkdown,
  renderProposals,
  summaryLines,
  formatWilson,
  fpBreakdown,
  renderFpBreakdown,
} = require('./protocol.js');
const { runEvasion, renderEvasion } = require('./evasion/scenarios.js');
const { runSweep } = require('./sweep.js');

/**
 * `eval/run.mjs --dataset <name> --zeek-logs <dir>`.
 * Writes `eval/results/<dataset>.json` and `.md`. IoT-23 is the wired joiner.
 * `--sweep <detector>.<param>=<from>:<to>:<step>` replays once per point instead.
 * With `--sweep`, `--dataset` and `--zeek-logs` are optional. Missing logs use the
 * synthetic fixture and label the result synthetic.
 * @param {string[]} argv
 * @param {{ outDir?: string, cacheDir?: string, quiet?: boolean, evasionPath?: string }} [opts]
 * @returns {any}
 */
function main(argv, opts = {}) {
  const args = parseArgs(argv);
  assertSplit(args);
  if (args.sweep) return runSweep(args, opts);
  const loaded = loadDataset(args.dataset, args.zeekLogs);
  const result = evaluate(loaded.rows, {
    tiers: loaded.tiers,
    dataset: args.dataset,
    alerts: true,
  });
  result.evasion = runEvasion();
  const dir = opts.outDir || path.join(__dirname, 'results');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${args.dataset}.json`), `${JSON.stringify(result, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, `${args.dataset}.md`), renderMarkdown(result));
  fs.writeFileSync(path.join(dir, `${args.dataset}.proposals.md`), renderProposals(result));
  const evasionPath = opts.evasionPath || path.join(__dirname, 'results', 'evasion.md');
  fs.mkdirSync(path.dirname(evasionPath), { recursive: true });
  fs.writeFileSync(evasionPath, renderEvasion(result.evasion));
  if (args.fpBreakdown) {
    const report = fpBreakdown(loaded.rows, { tiers: loaded.tiers, dataset: args.dataset });
    const breakdownDir = path.join(dir, args.dataset);
    fs.mkdirSync(breakdownDir, { recursive: true });
    const stored = { ...report };
    delete stored.proposals;
    fs.writeFileSync(
      path.join(breakdownDir, 'fp-breakdown.json'),
      `${JSON.stringify(stored, null, 2)}\n`,
    );
    fs.writeFileSync(path.join(breakdownDir, 'fp-breakdown.md'), renderFpBreakdown(stored));
    if (!opts.quiet) {
      for (const line of report.proposals) console.log(line);
    }
  }
  if (!opts.quiet) {
    for (const line of summaryLines(result)) console.log(line);
    if (args.labels) console.log(precisionLine(args.labels));
  }
  return result;
}

/**
 * Precision of operator labels, with a 95% Wilson interval.
 * True positives over tp + fp. The capture itself is still scored by C6.2.
 * @param {string} file
 * @returns {string}
 */
function precisionLine(file) {
  const text = fs.readFileSync(file, 'utf8');
  let tp = 0;
  let fp = 0;
  for (const line of text.split('\n')) {
    if (!line.trim()) continue;
    const row = JSON.parse(line);
    if (row.verdict === 'tp') tp += 1;
    else if (row.verdict === 'fp') fp += 1;
    else if (row.verdict !== 'benign-true' && row.verdict !== 'unknown') {
      throw new TypeError('verdict is invalid');
    }
  }
  return `precision: ${formatWilson(tp, tp + fp)}`;
}

/**
 * @param {string} dataset
 * @param {string} zeekLogs
 * @returns {{ rows: any[], tiers: string[] }}
 */
function loadDataset(dataset, zeekLogs) {
  if (dataset === 'iot23') return { rows: loadIot23(zeekLogs), tiers: ['T1'] };
  if (dataset === 'ciciot2023')
    return { rows: loadCiciot2023(zeekLogs), tiers: ['T1', 'T2', 'T3'] };
  if (dataset === 'ieee-dataport') return { rows: loadIeeeDataport(zeekLogs), tiers: ['T1', 'T4'] };
  if (dataset === 'ciciomt2024')
    return { rows: loadCiciomt2024(zeekLogs), tiers: ['T1', 'T2', 'T5'] };
  throw new TypeError(`no joiner for dataset ${dataset}`);
}

/**
 * A named split may run only the captures in that list.
 * @param {{ split?: string, splitFile?: string, dataset?: string }} args
 * @returns {void}
 */
function assertSplit(args) {
  if (!args.split) return;
  if (args.split !== 'tune' && args.split !== 'holdout') {
    throw new TypeError('split must be tune or holdout');
  }
  const file = args.splitFile || path.join(__dirname, 'splits', 'iot23.json');
  const lists = JSON.parse(fs.readFileSync(file, 'utf8'));
  const allowed = lists[args.split] || [];
  if (args.dataset && !allowed.includes(args.dataset)) {
    throw new TypeError(`${args.dataset} is not in the ${args.split} split`);
  }
}

/**
 * @param {string[]} argv
 * @returns {{ dataset?: string, zeekLogs?: string, labels?: string, fpBreakdown: boolean, sweep?: string, cost?: string, split?: string, splitFile?: string, fitLr?: boolean }}
 */
function parseArgs(argv) {
  /** @type {{ dataset?: string, zeekLogs?: string, labels?: string, fpBreakdown?: boolean, sweep?: string, cost?: string, split?: string, splitFile?: string, fitLr?: boolean }} */
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dataset') out.dataset = argv[(i += 1)];
    else if (arg === '--zeek-logs') out.zeekLogs = argv[(i += 1)];
    else if (arg === '--labels') out.labels = argv[(i += 1)];
    else if (arg === '--fp-breakdown') out.fpBreakdown = true;
    else if (arg === '--sweep') out.sweep = argv[(i += 1)];
    else if (arg === '--cost') out.cost = argv[(i += 1)];
    else if (arg === '--split') out.split = argv[(i += 1)];
    else if (arg === '--split-file') out.splitFile = argv[(i += 1)];
    else if (arg === '--fit-lr') out.fitLr = true;
    else throw new TypeError(`unknown argument ${arg}`);
    if (arg !== '--fp-breakdown' && arg !== '--fit-lr' && argv[i] == null)
      throw new TypeError(`missing value for ${arg}`);
  }
  if (out.split === 'holdout' && (out.sweep || out.cost || out.fitLr)) {
    throw new TypeError('holdout refuses --sweep, --cost, and fit-lr');
  }
  if (out.cost && !out.sweep) throw new TypeError('--cost requires --sweep');
  if (out.sweep) {
    if (out.fpBreakdown) throw new TypeError('sweep does not take --fp-breakdown');
    if (out.labels) throw new TypeError('sweep does not take --labels');
    return {
      dataset: out.dataset,
      zeekLogs: out.zeekLogs,
      sweep: out.sweep,
      cost: out.cost,
      split: out.split,
      splitFile: out.splitFile,
      fpBreakdown: false,
    };
  }
  if (!out.dataset || !out.zeekLogs) throw new TypeError('need --dataset and --zeek-logs');
  return {
    dataset: out.dataset,
    zeekLogs: out.zeekLogs,
    labels: out.labels,
    split: out.split,
    splitFile: out.splitFile,
    fpBreakdown: out.fpBreakdown === true,
  };
}

module.exports = { main, parseArgs };
