'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { LIMITS } = require('./limits.js');

/**
 * Weekly counts from the files already on disk. No network call.
 * @param {{ stateDir: string, weekStart: number, weekEnd: number, out: string }} opts
 * @returns {void}
 */
function writeReport(opts) {
  const counts = countEvents(opts.stateDir, opts.weekStart, opts.weekEnd);
  const labels = countLabels(opts.stateDir);
  const lines = ['# Pilot week', ''];
  lines.push(`Anomalies: ${counts.total}`);
  for (const [id, n] of counts.byDetector) {
    lines.push(`- ${id}: ${n}`);
  }
  lines.push('', 'Labels');
  for (const [id, row] of labels) {
    const text = row.n < LIMITS.labelsForRate ? `n too small (${row.n} labels)` : fpText(row);
    lines.push(`- ${id}: ${text}`);
  }
  lines.push('');
  fs.mkdirSync(path.dirname(opts.out), { recursive: true });
  fs.writeFileSync(opts.out, lines.join('\n'));
}

/**
 * @param {string} stateDir
 * @param {number} start
 * @param {number} end
 */
function countEvents(stateDir, start, end) {
  const byDetector = new Map();
  let total = 0;
  const dir = path.join(stateDir, 'events');
  if (!fs.existsSync(dir)) return { total, byDetector };
  for (const name of fs.readdirSync(dir)) {
    for (const line of fs.readFileSync(path.join(dir, name), 'utf8').split('\n')) {
      if (!line) continue;
      const row = JSON.parse(line);
      if (row.ts < start || row.ts >= end) continue;
      total += 1;
      byDetector.set(row.detector, (byDetector.get(row.detector) || 0) + 1);
    }
  }
  return { total, byDetector };
}

/**
 * @param {string} stateDir
 * @returns {Map<string, { n: number, fp: number }>}
 */
function countLabels(stateDir) {
  /** @type {Map<string, { n: number, fp: number }>} */
  const out = new Map();
  const file = path.join(stateDir, 'labels-applied.jsonl');
  if (!fs.existsSync(file)) return out;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (!line) continue;
    const row = JSON.parse(line);
    const id = row.detector || 'unknown';
    const cur = out.get(id) || { n: 0, fp: 0 };
    cur.n += 1;
    if (row.verdict === 'fp') cur.fp += 1;
    out.set(id, cur);
  }
  return out;
}

/**
 * @param {{ n: number, fp: number }} row
 * @returns {string}
 */
function fpText(row) {
  const p = row.fp / row.n;
  return `${row.fp}/${row.n} false positives (${p.toFixed(3)})`;
}

module.exports = { writeReport };
