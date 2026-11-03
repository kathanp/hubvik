#!/usr/bin/env node
'use strict';

/**
 * The tag workflow checks this before pack and publish.
 * GITHUB_REF must be refs/tags/vX.Y.Z and must match the core package and the lockfile.
 */

import { readFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/**
 * @param {string} ref
 * @returns {string}
 */
export function tagFromRef(ref) {
  const match = /^refs\/tags\/v(\d+\.\d+\.\d+)$/.exec(ref);
  return match ? match[1] : '';
}

/**
 * @param {string} tag
 * @param {string} coreVersion
 * @param {string} lockVersion
 * @returns {boolean}
 */
export function versionsMatch(tag, coreVersion, lockVersion) {
  return tag.length > 0 && tag === coreVersion && tag === lockVersion;
}

/**
 * @param {string} root
 * @param {string} ref
 * @returns {string}
 */
export function evaluate(root, ref) {
  const tag = tagFromRef(ref);
  const core = JSON.parse(readFileSync(join(root, 'packages/core/package.json'), 'utf8')).version;
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8')).packages?.[
    'packages/core'
  ]?.version;
  if (!versionsMatch(tag, core, lock)) {
    return `release version check failed: tag ${tag || '(none)'} core ${core} lock ${lock || '(none)'}`;
  }
  return '';
}

/**
 * @returns {void}
 */
function main() {
  const message = evaluate(ROOT, process.env.GITHUB_REF || '');
  if (message) {
    console.error(message);
    process.exit(1);
  }
  console.log(
    `release version ${tagFromRef(process.env.GITHUB_REF || '')} matches core and the lock`,
  );
}

const invoked = process.argv[1];
if (invoked && realpathSync(invoked) === realpathSync(fileURLToPath(import.meta.url))) main();
