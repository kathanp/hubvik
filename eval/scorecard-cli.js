'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { BY_ID } = require('../packages/core/src/detectors/index.js');
const { rowsFromResult } = require('./scorecard.js');

/**
 * @param {string} resultsDir
 * @param {string} splitFile
 * @returns {any[]}
 */
function collect(resultsDir, splitFile) {
  const lists = JSON.parse(fs.readFileSync(splitFile, 'utf8'));
  const registry = new Map(
    Object.values(BY_ID).map((det) => [
      det.id,
      {
        mode: det.meta && det.meta.mode === 'shadow' ? 'shadow' : 'live',
        hardRule: det.hardRule === true,
      },
    ]),
  );
  /** @type {any[]} */
  const rows = [];
  for (const file of jsonFiles(resultsDir)) {
    if (path.basename(file) === 'scorecard.json') continue;
    const result = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!Array.isArray(result.ablation)) continue;
    const parent = path.basename(path.dirname(file));
    const name =
      (lists.tune || []).includes(parent) || (lists.holdout || []).includes(parent)
        ? parent
        : result.dataset || parent;
    const split = (lists.tune || []).includes(name)
      ? 'tune'
      : (lists.holdout || []).includes(name)
        ? 'holdout'
        : 'unlisted';
    rows.push(...rowsFromResult(result, split, registry));
  }
  return rows;
}

/**
 * @param {string} dir
 * @returns {string[]}
 */
function jsonFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...jsonFiles(full));
    else if (entry.name.endsWith('.json')) out.push(full);
  }
  return out.sort();
}

/**
 * @param {any[]} rows
 * @returns {string}
 */
function render(rows) {
  const lines = ['# Scorecard', '', 'Suggestions are proposals. They do not edit a default.', ''];
  for (const row of rows) {
    const rate = row.fpPerBenignDeviceDay == null ? 'no rate' : String(row.fpPerBenignDeviceDay);
    const interval = row.wilson95
      ? `Wilson 95% ${row.wilson95.low} to ${row.wilson95.high}`
      : 'no Wilson interval';
    const unique = row.nTooSmall
      ? `n too small (${row.uniqueDetections} unique detections)`
      : String(row.uniqueDetections);
    lines.push(
      `- ${row.id} ${row.split} ${row.mode} suggestion ${row.suggestion}; unique ${unique}; FP per benign device-day ${rate}; ${interval}`,
    );
  }
  lines.push('');
  return lines.join('\n');
}

/**
 * @param {{ resultsDir?: string, splitFile?: string, outDir?: string }} [opts]
 * @returns {any[]}
 */
function writeScorecard(opts = {}) {
  const root = path.join(__dirname);
  const resultsDir = opts.resultsDir || path.join(root, 'results');
  const splitFile = opts.splitFile || path.join(root, 'splits', 'iot23.json');
  const outDir = opts.outDir || resultsDir;
  const rows = collect(resultsDir, splitFile);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'scorecard.json'), `${JSON.stringify(rows, null, 2)}\n`);
  fs.writeFileSync(path.join(outDir, 'scorecard.md'), render(rows));
  return rows;
}

module.exports = { writeScorecard, render };
