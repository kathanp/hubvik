'use strict';

const { readFileSync, readdirSync } = require('node:fs');
const { join } = require('node:path');

const SKIP_FILES = new Set(['index.js', 'lib.js', 'state.js', 'samples.js']);
const HELPER = /explain(?:Threshold|NewMember|Changed|Match)\(/;

/**
 * Live detectors must set meta.explains and call an explain helper.
 * Shadow detectors are skipped. D-131 is a check target, not a detection rate.
 * @param {string} dir
 * @param {(file: string) => any} load
 * @returns {{ live: number, explained: number, problems: string[] }}
 */
function liveExplainProblems(dir, load) {
  let live = 0;
  let explained = 0;
  /** @type {string[]} */
  const problems = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith('.js') || SKIP_FILES.has(file)) continue;
    const full = join(dir, file);
    const detector = load(full);
    if (!detector || (detector.meta && detector.meta.mode === 'shadow')) continue;
    live += 1;
    const source = readFileSync(full, 'utf8');
    const id = typeof detector.id === 'string' ? detector.id : file;
    if (detector.meta && detector.meta.explains === true && HELPER.test(source)) {
      explained += 1;
      continue;
    }
    problems.push(`${id} live detector has no explain`);
  }
  return { live, explained, problems };
}

module.exports = { liveExplainProblems };
