#!/usr/bin/env node
'use strict';

/**
 * Fail the build when a publishable workspace tarball is unsafe or overweight.
 * Checks npm pack --dry-run output. Does not publish.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const MAX_UNPACKED = 500 * 1024;
const CORE_UNPACKED = 750 * 1024;
const MAX_FILE = 60 * 1024;
const MAX_DATA = 200 * 1024;
const ALLOWED = new Set(['package.json', 'README.md', 'LICENSE', 'CHANGELOG.md', 'SECURITY.md']);
const TOKEN = /npm_[A-Za-z0-9]{36}|ghp_|github_pat_/;
const BANNED = ['TODO', 'FIXME', 'console.log'];

/**
 * @param {string} message
 */
function fail(message) {
  console.error(`pack-check: ${message}`);
  process.exitCode = 1;
}

/**
 * @returns {string[]}
 */
function publishableWorkspaces() {
  const dir = join(ROOT, 'packages');
  return readdirSync(dir)
    .map((name) => join(dir, name))
    .filter((path) => statSync(path).isDirectory())
    .filter((path) => {
      const pkg = JSON.parse(readFileSync(join(path, 'package.json'), 'utf8'));
      return pkg.private !== true;
    });
}

/**
 * @param {string} raw
 * @returns {any}
 */
function parsePackJson(raw) {
  const start = raw.indexOf('[');
  const obj = raw.indexOf('{');
  const cut = start === -1 ? obj : obj === -1 ? start : Math.min(start, obj);
  if (cut === -1) throw new Error('npm pack produced no JSON');
  return JSON.parse(raw.slice(cut));
}

/**
 * @param {string} filePath
 * @returns {boolean}
 */
function pathAllowed(filePath) {
  const normalized = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  if (ALLOWED.has(normalized)) return true;
  return normalized.startsWith('src/');
}

/**
 * @param {string} workspace
 */
function checkWorkspace(workspace) {
  const rel = relative(ROOT, workspace);
  const pkg = JSON.parse(readFileSync(join(workspace, 'package.json'), 'utf8'));
  const deps = pkg.dependencies;
  if (rel === 'packages/core') {
    if (!deps || typeof deps !== 'object' || Array.isArray(deps) || Object.keys(deps).length > 0) {
      fail(`${rel} dependencies must be an empty object`);
    }
  }

  const raw = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
    cwd: workspace,
    encoding: 'utf8',
  });
  const parsed = parsePackJson(raw);
  const entry = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!entry || !Array.isArray(entry.files)) {
    fail(`${rel} npm pack JSON has no files array`);
    return;
  }

  const unpacked =
    typeof entry.unpackedSize === 'number'
      ? entry.unpackedSize
      : entry.files.reduce((sum, file) => sum + (file.size || 0), 0);
  const cap = rel === 'packages/core' ? CORE_UNPACKED : MAX_UNPACKED;
  if (unpacked > cap) {
    fail(`${rel} unpacked size ${unpacked} exceeds ${cap}`);
  }

  if (rel === 'packages/core') {
    const ranked = entry.files.slice().sort((a, b) => (b.size || 0) - (a.size || 0));
    console.log(`${rel} largest packed files:`);
    for (const file of ranked.slice(0, 15)) {
      console.log(`  ${file.size} ${file.path}`);
    }
    let dataBytes = 0;
    for (const file of entry.files) {
      const filePath = String(file.path || '')
        .replace(/\\/g, '/')
        .replace(/^\.\//, '');
      const size = file.size || 0;
      if (filePath.startsWith('src/data/')) dataBytes += size;
      if (size > MAX_FILE) {
        fail(`${rel} ${filePath} is ${size} bytes, over 60 KB`);
      }
    }
    if (dataBytes > MAX_DATA) {
      fail(`${rel} src/data total ${dataBytes} exceeds ${MAX_DATA}`);
    }
  }

  for (const file of entry.files) {
    const filePath = String(file.path || '');
    if (!pathAllowed(filePath)) {
      fail(`${rel} packs disallowed file ${filePath}`);
      continue;
    }
    const text = readFileSync(join(workspace, filePath), 'utf8');
    for (const word of BANNED) {
      if (text.includes(word)) fail(`${rel} ${filePath} contains ${word}`);
    }
    if (TOKEN.test(text)) fail(`${rel} ${filePath} matches a token pattern`);
    if (
      rel === 'packages/respond-nftables' &&
      /require\((['"])(?:node:)?(?:child_process|worker_threads)\1\)/.test(text)
    ) {
      fail(`${rel} ${filePath} must not require child_process or worker_threads`);
    }
  }

  if (process.exitCode) return;
  console.log(`${rel}: ${entry.files.length} files, ${unpacked} bytes unpacked`);
}

const workspaces = publishableWorkspaces();
if (workspaces.length === 0) {
  fail('no publishable workspaces');
} else {
  for (const workspace of workspaces) checkWorkspace(workspace);
}

if (process.exitCode) process.exit(process.exitCode);
console.log('pack-check: ok');
