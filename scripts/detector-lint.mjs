#!/usr/bin/env node
'use strict';

/**
 * Fail when a detector import drops an oversize array instead of throwing.
 * A silent return leaves the device with an empty baseline and no error.
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIR = join(ROOT, 'packages/core/src/detectors');
const SILENT = /state\.[A-Za-z0-9_]+\.length\s*>\s*\d+\)\s*return/;

let failed = false;
for (const name of readdirSync(DIR)) {
  if (!name.endsWith('.js') || name === 'index.js' || name === 'state.js') continue;
  const text = readFileSync(join(DIR, name), 'utf8');
  const start = text.indexOf('importState');
  if (start < 0) continue;
  const body = text.slice(start);
  if (SILENT.test(body)) {
    console.error(`detector-lint: ${name} importState returns on an oversize array`);
    failed = true;
  }
}

if (failed) process.exit(1);
console.log('detector-lint: ok');
