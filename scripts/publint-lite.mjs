#!/usr/bin/env node
'use strict';

/**
 * Check the publish fields of every public package. Does not publish.
 */

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PACKAGES = join(ROOT, 'packages');

/**
 * @param {string} message
 */
function fail(message) {
  console.error(`publint-lite: ${message}`);
  process.exitCode = 1;
}

for (const name of readdirSync(PACKAGES).sort()) {
  const dir = join(PACKAGES, name);
  if (!statSync(dir).isDirectory()) continue;
  const pkgPath = join(dir, 'package.json');
  if (!existsSync(pkgPath)) continue;
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
  if (pkg.private === true) continue;
  if (typeof pkg.name !== 'string' || pkg.name.length === 0) fail(`${name} missing name`);
  if (typeof pkg.version !== 'string') fail(`${name} missing version`);
  if (pkg.license !== 'Apache-2.0') fail(`${name} license must be Apache-2.0`);
  if (!pkg.dependencies || Object.keys(pkg.dependencies).length !== 0) {
    fail(`${name} dependencies must be empty`);
  }
  const entry = pkg.exports && pkg.exports['.'];
  for (const field of ['types', 'import', 'require']) {
    if (!entry || typeof entry[field] !== 'string')
      fail(`${name} exports["."].${field} is missing`);
  }
  for (const rel of [pkg.main, pkg.types, entry && entry.import, entry && entry.require]) {
    if (typeof rel !== 'string' || !existsSync(join(dir, rel))) fail(`${name} missing file ${rel}`);
  }
}

if (process.exitCode) process.exit(process.exitCode);
console.log('publint-lite: ok');
