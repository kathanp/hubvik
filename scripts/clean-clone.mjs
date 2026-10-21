#!/usr/bin/env node
/**
 * 9a clones this repo to a temporary directory and runs npm ci and npm run gate.
 * 9b packs each public tarball, installs it, and runs the examples/01 feed under CJS and ESM.
 * `--pack-only` runs 9b in this tree and skips the clone.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const packOnly = process.argv.includes('--pack-only');

/**
 * @param {string} cwd
 * @param {string} cmd
 * @param {string[]} args
 */
function run(cwd, cmd, args) {
  execFileSync(cmd, args, { cwd, stdio: 'inherit' });
}

/**
 * @param {string} root
 * @returns {string[]}
 */
function workspaces(root) {
  return readdirSync(join(root, 'packages'))
    .map((name) => join(root, 'packages', name))
    .filter((dir) => statSync(dir).isDirectory())
    .filter((dir) => JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')).private !== true);
}

/**
 * Install each packed tarball and run the camera-free feed from examples/01.
 * @param {string} root
 */
function packAndRun(root) {
  const dir = mkdtempSync(join(tmpdir(), 'hubvik-pack-'));
  try {
    const tarballs = [];
    for (const workspace of workspaces(root)) {
      const out = execFileSync('npm', ['pack', '--json', '--ignore-scripts'], {
        cwd: workspace,
        encoding: 'utf8',
      });
      const packed = JSON.parse(out.slice(out.indexOf('[')));
      const file = join(workspace, packed[0].filename);
      tarballs.push(file);
    }
    const hubvik = tarballs.find((file) => /\/core\/hubvik-/.test(file));
    if (!hubvik) throw new Error('core tarball was not packed');
    writeFileSync(
      join(dir, 'package.json'),
      `${JSON.stringify({ name: 'hubvik-pack-smoke', private: true, type: 'module' }, null, 2)}\n`,
    );
    run(dir, 'npm', ['install', hubvik]);
    writeFileSync(
      join(dir, 'cjs.cjs'),
      `'use strict';\nconst { createEngine } = require('hubvik');\nconst engine = createEngine({ learnMs: 0 });\nconst rows = [];\nengine.on('anomaly', (row) => rows.push(row.detector));\nengine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });\nengine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 2000 });\nif (!rows.includes('new-destination')) process.exit(1);\n`,
    );
    writeFileSync(
      join(dir, 'esm.mjs'),
      `import { createEngine } from 'hubvik';\nconst engine = createEngine({ learnMs: 0 });\nconst rows = [];\nengine.on('anomaly', (row) => rows.push(row.detector));\nengine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });\nengine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 2000 });\nif (!rows.includes('new-destination')) process.exit(1);\n`,
    );
    const pkg = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
    delete pkg.type;
    writeFileSync(join(dir, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
    run(dir, 'node', ['cjs.cjs']);
    pkg.type = 'module';
    writeFileSync(join(dir, 'package.json'), `${JSON.stringify(pkg, null, 2)}\n`);
    run(dir, 'node', ['esm.mjs']);
    console.log(
      `clean-clone: packed ${tarballs.length} tarball(s); examples/01 feed passed under CJS and ESM`,
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
    for (const workspace of workspaces(root)) {
      for (const name of readdirSync(workspace)) {
        if (name.endsWith('.tgz')) rmSync(join(workspace, name), { force: true });
      }
    }
  }
}

if (packOnly) {
  packAndRun(ROOT);
} else {
  const dir = mkdtempSync(join(tmpdir(), 'hubvik-clone-'));
  try {
    run(ROOT, 'git', ['clone', '--local', ROOT, dir]);
    run(dir, 'npm', ['ci']);
    run(dir, 'npm', ['run', 'gate']);
    packAndRun(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
