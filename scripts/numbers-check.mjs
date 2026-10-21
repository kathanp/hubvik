#!/usr/bin/env node
/**
 * Every percentage or per-device-day figure in the public READMEs and the
 * handoff notes must cite an eval/results file that contains that figure.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/**
 * @param {string} dir
 * @param {string[]} out
 */
function walkReadmes(dir, out) {
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name);
    if (!statSync(abs).isDirectory()) continue;
    const readme = join(abs, 'README.md');
    if (existsSync(readme)) out.push(readme);
  }
}

/**
 * @returns {string[]}
 */
function files() {
  /** @type {string[]} */
  const out = [join(ROOT, 'README.md')];
  walkReadmes(join(ROOT, 'packages'), out);
  const handoff = join(ROOT, 'docs', 'handoff');
  if (existsSync(handoff)) {
    for (const name of readdirSync(handoff)) {
      if (name.endsWith('.md')) out.push(join(handoff, name));
    }
  }
  return out;
}

const FIGURE = /\d+(?:\.\d+)?%|\d+(?:\.\d+)?(?=\s+per(?:\s+benign)?\s+device-day)/g;
const CITE = /eval\/results\/[A-Za-z0-9_./-]+/g;

/**
 * @param {string} file
 * @param {string[]} errors
 */
function check(file, errors) {
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, index) => {
    const figures = line.match(FIGURE);
    if (!figures) return;
    const window = lines.slice(Math.max(0, index - 3), index + 4).join('\n');
    const cites = window.match(CITE) || [];
    const cited = cites.find((rel) => existsSync(join(ROOT, rel)));
    const where = `${file}:${index + 1}`;
    if (!cited) {
      errors.push(`${where} figure ${figures.join(', ')} has no eval/results path within 3 lines`);
      return;
    }
    const body = readFileSync(join(ROOT, cited), 'utf8');
    for (const figure of figures) {
      if (!body.includes(figure)) errors.push(`${where} ${figure} is not in ${cited}`);
    }
  });
}

const errors = [];
for (const file of files()) check(file, errors);
if (errors.length) {
  console.error(`numbers-check: FAIL (${errors.length})`);
  for (const line of errors) console.error(`  - ${line}`);
  process.exit(1);
}
console.log('numbers-check: ok');
