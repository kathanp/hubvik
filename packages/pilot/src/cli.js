#!/usr/bin/env node
'use strict';

const { createRunner } = require('./index.js');
const { writeReport } = require('./report.js');
const { queueLabel } = require('./inbox.js');
const { LIMITS } = require('./limits.js');

const argv = process.argv.slice(2);
const command = argv[0];

if (command === 'run') run(flags(argv.slice(1)));
else if (command === 'label') label(flags(argv.slice(1)), argv);
else if (command === 'report') report(flags(argv.slice(1)));
else if (command === 'export-labels') exportLabels(flags(argv.slice(1)));
else {
  process.stderr.write('hubvik-pilot <run|label|report|export-labels>\n');
  process.exit(1);
}

/**
 * @param {Record<string, string>} opts
 */
function run(opts) {
  const runner = createRunner({
    stateDir: need(opts, 'state'),
    conntrack: opts.conntrack,
    dnsmasq: opts.dnsmasq,
  });
  const timer = setInterval(() => runner.step(Date.now()), LIMITS.pollMs);
  const halt = () => {
    clearInterval(timer);
    runner.stop(Date.now());
    process.exit(0);
  };
  process.on('SIGTERM', halt);
  process.on('SIGINT', halt);
}

/**
 * @param {Record<string, string>} opts
 * @param {string[]} argv
 */
function label(opts, argv) {
  const key = argv[1];
  const verdict = argv[2];
  if (!key || !verdict) throw new Error('label needs a key and a verdict');
  queueLabel(need(opts, 'state'), { key, verdict });
}

/**
 * @param {Record<string, string>} opts
 */
function report(opts) {
  const start = Date.parse(`${need(opts, 'week')}-1`);
  writeReport({
    stateDir: need(opts, 'state'),
    weekStart: start,
    weekEnd: start + 7 * 24 * 3600e3,
    out: need(opts, 'out'),
  });
}

/**
 * @param {Record<string, string>} opts
 */
function exportLabels(opts) {
  const fs = require('node:fs');
  const runner = createRunner({ stateDir: need(opts, 'state') });
  fs.writeFileSync(need(opts, 'out'), runner.engine.exportLabels());
}

/**
 * @param {string[]} argv
 * @returns {Record<string, string>}
 */
function flags(argv) {
  /** @type {Record<string, string>} */
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    out[arg.slice(2)] = argv[i + 1];
    i += 1;
  }
  return out;
}

/**
 * @param {Record<string, string>} opts
 * @param {string} key
 * @returns {string}
 */
function need(opts, key) {
  if (!opts[key]) throw new Error(`missing --${key}`);
  return opts[key];
}
