'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { loadIot23 } = require('./iot23.js');
const { loadCiciot2023 } = require('./ciciot2023.js');
const {
  evaluate,
  renderMarkdown,
  renderProposals,
  summaryLines,
  formatWilson,
} = require('./protocol.js');
const { runEvasion, renderEvasion } = require('./evasion/scenarios.js');

/**
 * `eval/run.mjs --dataset <name> --zeek-logs <dir>`.
 * Writes `eval/results/<dataset>.json` and `.md`. IoT-23 is the wired joiner.
 * @param {string[]} argv
 * @param {{ outDir?: string }} [opts]
 * @returns {any}
 */
function main(argv, opts = {}) {
  const args = parseArgs(argv);
  const loaded = loadDataset(args.dataset, args.zeekLogs);
  const result = evaluate(loaded.rows, { tiers: loaded.tiers, dataset: args.dataset });
  result.evasion = runEvasion();
  const dir = opts.outDir || path.join(__dirname, 'results');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${args.dataset}.json`), `${JSON.stringify(result, null, 2)}\n`);
  fs.writeFileSync(path.join(dir, `${args.dataset}.md`), renderMarkdown(result));
  fs.writeFileSync(path.join(dir, `${args.dataset}.proposals.md`), renderProposals(result));
  const evasionPath = opts.evasionPath || path.join(__dirname, 'results', 'evasion.md');
  fs.mkdirSync(path.dirname(evasionPath), { recursive: true });
  fs.writeFileSync(evasionPath, renderEvasion(result.evasion));
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
  throw new TypeError(`no joiner for dataset ${dataset}`);
}

/**
 * @param {string[]} argv
 * @returns {{ dataset: string, zeekLogs: string, labels?: string }}
 */
function parseArgs(argv) {
  /** @type {{ dataset?: string, zeekLogs?: string, labels?: string }} */
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dataset') out.dataset = argv[(i += 1)];
    else if (arg === '--zeek-logs') out.zeekLogs = argv[(i += 1)];
    else if (arg === '--labels') out.labels = argv[(i += 1)];
    else throw new TypeError(`unknown argument ${arg}`);
  }
  if (!out.dataset || !out.zeekLogs) throw new TypeError('need --dataset and --zeek-logs');
  return { dataset: out.dataset, zeekLogs: out.zeekLogs, labels: out.labels };
}

module.exports = { main, parseArgs };
