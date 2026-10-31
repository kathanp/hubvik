#!/usr/bin/env node
/**
 * Read-only drift check for the documentation reconciliation.
 * Exit 1 when a version line, a package version claim, a SPEC decision id,
 * a repeated decision id, or the old ERRORS.md fix boilerplate is wrong.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** @type {string[]} */
const failures = [];

/**
 * @param {string} file
 * @param {number} line
 * @param {string} message
 */
function fail(file, line, message) {
  failures.push(`${file}:${line} ${message}`);
}

/**
 * @param {string} rel
 * @returns {string}
 */
function read(rel) {
  return readFileSync(join(ROOT, rel), 'utf8');
}

/**
 * Dated records and the historical spec keep old version strings on purpose.
 * @param {string} rel
 * @returns {boolean}
 */
function skipVersionClaim(rel) {
  if (rel.endsWith('CHANGELOG.md')) return true;
  if (rel.startsWith('docs/adr/')) return true;
  if (rel.startsWith('docs/current/')) return true;
  if (rel.startsWith('docs/handoff/')) return true;
  if (rel.startsWith('docs/progress/')) return true;
  if (rel === 'docs/DECISIONS.md' || rel === 'docs/BENCHMARKS.md') return true;
  if (rel === 'docs/QUESTIONS.md' || rel === 'docs/SPEC.md') return true;
  if (rel === 'docs/ERRORS.md') return true;
  if (rel === 'packages/core/README.md') return true;
  return false;
}

/**
 * @param {string} dir
 * @param {string[]} out
 * @returns {void}
 */
function walkMd(dir, out) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules') continue;
    const abs = join(dir, name);
    const st = statSync(abs);
    if (st.isDirectory()) walkMd(abs, out);
    else if (name.endsWith('.md')) out.push(abs);
  }
}

/**
 * @returns {Map<string, string>}
 */
function packageVersions() {
  /** @type {Map<string, string>} */
  const versions = new Map();
  const root = join(ROOT, 'packages');
  for (const name of readdirSync(root)) {
    const pkgPath = join(root, name, 'package.json');
    if (!existsSync(pkgPath)) continue;
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    versions.set(pkg.name, pkg.version);
  }
  return versions;
}

/**
 * @returns {void}
 */
function checkVersionLines() {
  const protPath = join(ROOT, '.autopilot', 'protected.json');
  if (!existsSync(protPath)) return;
  const prot = JSON.parse(readFileSync(protPath, 'utf8'));
  const versioned = prot.docs && Array.isArray(prot.docs.versioned) ? prot.docs.versioned : [];
  const core = JSON.parse(read(join('packages', 'core', 'package.json')));
  const needle = `> Version: ${core.version}`;
  for (const rel of versioned) {
    const abs = join(ROOT, rel);
    if (!existsSync(abs)) {
      fail(rel, 1, 'listed in docs.versioned but the file is missing');
      continue;
    }
    const head = readFileSync(abs, 'utf8').split('\n').slice(0, 5);
    if (!head.some((line) => line.includes(needle))) {
      fail(rel, 1, `missing "${needle}" in the first 5 lines`);
    }
  }
}

/**
 * @param {Map<string, string>} versions
 * @returns {void}
 */
function checkVersionClaims(versions) {
  /** @type {string[]} */
  const files = [];
  walkMd(ROOT, files);
  const coreVersion = versions.get('hubvik');
  for (const abs of files) {
    const rel = relative(ROOT, abs);
    if (skipVersionClaim(rel)) continue;
    const lines = readFileSync(abs, 'utf8').split('\n');
    lines.forEach((line, index) => {
      for (const match of line.matchAll(/hubvik@(\d+\.\d+\.\d+)/g)) {
        if (match[1] !== coreVersion) {
          fail(rel, index + 1, `hubvik@${match[1]} does not match packages/core ${coreVersion}`);
        }
      }
      for (const match of line.matchAll(/@hubvik\/([a-z0-9-]+)\s+(\d+\.\d+\.\d+)/g)) {
        const name = `@hubvik/${match[1]}`;
        const expected = versions.get(name);
        if (expected && match[2] !== expected) {
          fail(rel, index + 1, `${name} ${match[2]} does not match package.json ${expected}`);
        }
      }
    });
  }
}

/**
 * @returns {void}
 */
function checkDecisions() {
  if (!existsSync(join(ROOT, 'docs/DECISIONS.md'))) {
    console.log('docs-facts-check: docs/DECISIONS.md is absent; D-id check skipped');
    return;
  }
  const spec = read('docs/SPEC.md');
  const decisions = read('docs/DECISIONS.md');
  /** @type {Set<string>} */
  const present = new Set();
  /** @type {Map<string, number>} */
  const starts = new Map();
  decisions.split('\n').forEach((line, index) => {
    const match = line.match(/^D-(\d+)\s/);
    if (!match) return;
    const id = `D-${match[1]}`;
    present.add(id);
    starts.set(id, (starts.get(id) || 0) + 1);
    if (starts.get(id) > 1) {
      fail('docs/DECISIONS.md', index + 1, `${id} starts more than one entry`);
    }
  });
  const specLines = spec.split('\n');
  specLines.forEach((line, index) => {
    for (const match of line.matchAll(/\bD-(\d+)\b/g)) {
      const id = `D-${match[1]}`;
      if (!present.has(id))
        fail('docs/SPEC.md', index + 1, `${id} is missing from docs/DECISIONS.md`);
    }
  });
}

/**
 * @returns {void}
 */
function checkErrorsBoilerplate() {
  const lines = read('docs/ERRORS.md').split('\n');
  lines.forEach((line, index) => {
    if (line.includes('change the value that failed the check')) {
      fail('docs/ERRORS.md', index + 1, 'old boilerplate Fix line');
    }
  });
}

checkVersionLines();
checkVersionClaims(packageVersions());
checkDecisions();
checkErrorsBoilerplate();

if (failures.length > 0) {
  console.error(`docs-facts-check: FAIL (${failures.length})`);
  for (const line of failures) console.error(line);
  process.exit(1);
}
console.log('docs-facts-check: ok');
