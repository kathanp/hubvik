'use strict';

const { execFileSync } = require('node:child_process');
const { existsSync, readdirSync, readFileSync } = require('node:fs');
const { join } = require('node:path');

const SKIP = new Set(['index.js', 'lib.js', 'state.js', 'samples.js']);

/**
 * Detector ids on disk.
 * @param {string} dir
 * @returns {string[]}
 */
function detectorIds(dir) {
  return readdirSync(dir)
    .filter((name) => name.endsWith('.js') && !SKIP.has(name))
    .map((name) => name.slice(0, -3))
    .sort();
}

/**
 * C10 row 0.6 is ticked when its Met cell contains [x] or [X].
 * @param {string} spec
 * @returns {boolean}
 */
function row06Ticked(spec) {
  const line = spec.split('\n').find((row) => row.startsWith('| **0.6**'));
  if (!line) return false;
  const cells = line
    .split('|')
    .map((cell) => cell.trim())
    .filter(Boolean);
  const met = cells[cells.length - 1] || '';
  return /\[x\]/i.test(met);
}

/**
 * Ids in the freeze file on main, or null when that file is not there yet.
 * @param {string} root
 * @returns {string[] | null}
 */
function idsOnMain(root) {
  try {
    const text = execFileSync('git', ['show', 'main:scripts/autopilot/detector-freeze.json'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const parsed = JSON.parse(text);
    return Array.isArray(parsed.ids) ? parsed.ids : [];
  } catch {
    return null;
  }
}

/**
 * @param {{ root: string, spec?: string, ids?: string[], baseIds?: string[] | null }} [opts]
 * @returns {string[]}
 */
function checkFreeze(opts = {}) {
  const root = opts.root;
  const spec = opts.spec == null ? readFileSync(join(root, 'docs/SPEC.md'), 'utf8') : opts.spec;
  /** @type {string[]} */
  const problems = [];
  if (row06Ticked(spec)) return problems;
  const freezePath = join(root, 'scripts/autopilot/detector-freeze.json');
  if (!existsSync(freezePath)) {
    problems.push('detector-freeze.json is missing while C10 row 0.6 is unticked');
    return problems;
  }
  const freeze = JSON.parse(readFileSync(freezePath, 'utf8'));
  const listed = new Set(freeze.ids || []);
  const onDisk = opts.ids || detectorIds(join(root, 'packages/core/src/detectors'));
  for (const id of onDisk) {
    if (!listed.has(id)) problems.push(`detector ${id} added while the 0.6 gate is open`);
  }
  const base = opts.baseIds === undefined ? idsOnMain(root) : opts.baseIds;
  if (base) {
    const known = new Set(base);
    for (const id of freeze.ids || []) {
      if (!known.has(id))
        problems.push(`detector freeze list grew with ${id} without ticking C10 row 0.6`);
    }
  }
  return problems;
}

module.exports = { checkFreeze, detectorIds, row06Ticked };
