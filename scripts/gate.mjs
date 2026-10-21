#!/usr/bin/env node
'use strict';

/**
 * Run the release gate. A failed step does not stop the later steps.
 * Fuzz runs before the bench. The process exits non-zero after listing every failure.
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/** @type {[string, string, string[]][]} */
const STEPS = [
  ['check', 'npm', ['run', 'check']],
  ['coverage', 'npm', ['run', 'coverage']],
  ['pack:check', 'npm', ['run', 'pack:check']],
  ['spec-coverage', process.execPath, ['scripts/spec-coverage.mjs']],
  ['numbers-check', process.execPath, ['scripts/numbers-check.mjs']],
  ['no-dynamic', process.execPath, ['scripts/no-dynamic.mjs']],
  ['knip', 'npm', ['run', 'knip']],
  ['detector-lint', process.execPath, ['scripts/detector-lint.mjs']],
  ['publint-lite', process.execPath, ['scripts/publint-lite.mjs']],
  ['api-snapshot', process.execPath, ['scripts/api-snapshot.mjs']],
  ['fuzz', 'npm', ['run', 'fuzz']],
  ['bench', process.execPath, ['--expose-gc', 'bench/run.js']],
];

/**
 * @returns {void}
 */
function main() {
  /** @type {string[]} */
  const failed = [];
  for (const [name, command, args] of STEPS) {
    console.log(`\n--- gate: ${name} ---`);
    const result = spawnSync(command, args, { cwd: ROOT, stdio: 'inherit' });
    if (result.status !== 0) {
      const how = result.status == null ? `signal ${result.signal}` : `exit ${result.status}`;
      failed.push(`${name} (${how})`);
    }
  }
  if (failed.length > 0) {
    console.error('\ngate failed:');
    for (const line of failed) console.error(`- ${line}`);
    process.exit(1);
  }
  console.log('\ngate: ok');
}

main();
