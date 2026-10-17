'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { loadIot23 } = require('./iot23.js');
const { evaluate, renderMarkdown, renderProposals, summaryLines } = require('./protocol.js');
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
  if (args.dataset !== 'iot23') throw new TypeError(`no joiner for dataset ${args.dataset}`);
  const result = evaluate(loadIot23(args.zeekLogs), { tiers: ['T1'], dataset: args.dataset });
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
  }
  return result;
}

/**
 * @param {string[]} argv
 * @returns {{ dataset: string, zeekLogs: string }}
 */
function parseArgs(argv) {
  /** @type {{ dataset?: string, zeekLogs?: string }} */
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dataset') out.dataset = argv[(i += 1)];
    else if (arg === '--zeek-logs') out.zeekLogs = argv[(i += 1)];
    else throw new TypeError(`unknown argument ${arg}`);
  }
  if (!out.dataset || !out.zeekLogs) throw new TypeError('need --dataset and --zeek-logs');
  return { dataset: out.dataset, zeekLogs: out.zeekLogs };
}

module.exports = { main, parseArgs };
