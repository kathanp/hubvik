#!/usr/bin/env node
/**
 * Packed files must not spawn processes, eval, or build a require from a variable.
 * `npm audit --omit=dev` must report zero vulnerabilities.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const BANNED = [
  [/\b(?:node:)?child_process\b/, 'child_process'],
  [/\beval\s*\(/, 'eval'],
  [/\bnew\s+Function\s*\(/, 'new Function'],
  [/require\s*\(\s*[^'"`\s]/, 'non-literal require'],
];

/**
 * @param {string} message
 */
function fail(message) {
  console.error(`no-dynamic: ${message}`);
  process.exitCode = 1;
}

/**
 * @returns {string[]}
 */
function workspaces() {
  return readdirSync(join(ROOT, 'packages'))
    .map((name) => join(ROOT, 'packages', name))
    .filter((dir) => statSync(dir).isDirectory())
    .filter((dir) => {
      const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
      return pkg.private !== true;
    });
}

/**
 * @param {string} raw
 */
function parsePack(raw) {
  const start = raw.indexOf('[');
  const obj = raw.indexOf('{');
  const cut = start === -1 ? obj : obj === -1 ? start : Math.min(start, obj);
  if (cut < 0) throw new Error('npm pack produced no JSON');
  return JSON.parse(raw.slice(cut));
}

for (const dir of workspaces()) {
  const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: dir,
    encoding: 'utf8',
  });
  const packed = parsePack(raw);
  const entry = Array.isArray(packed) ? packed[0] : packed;
  for (const file of entry.files || []) {
    const name = String(file.path || file.name || '');
    if (!name.endsWith('.js') && !name.endsWith('.mjs') && !name.endsWith('.cjs')) continue;
    const text = readFileSync(join(dir, name), 'utf8');
    for (const [re, label] of BANNED) {
      if (re.test(text)) fail(`${relative(ROOT, join(dir, name))} contains ${label}`);
    }
  }
}

const audit = execFileSync('npm', ['audit', '--omit=dev', '--json'], {
  cwd: ROOT,
  encoding: 'utf8',
});
const report = JSON.parse(audit);
const vulns = report.metadata && report.metadata.vulnerabilities;
const total = vulns
  ? Object.values(vulns).reduce((sum, n) => sum + (typeof n === 'number' ? n : 0), 0)
  : 0;
if (total !== 0) fail(`npm audit --omit=dev reported ${total}`);
if (process.exitCode) process.exit(process.exitCode);
console.log('no-dynamic: ok');
