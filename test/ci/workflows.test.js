'use strict';

const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const ROOT = join(__dirname, '..', '..');

/**
 * @param {string} rel
 * @returns {string}
 */
function text(rel) {
  return readFileSync(join(ROOT, rel), 'utf8');
}

test('the pull request gate is Ubuntu Node 22 on the head commit', () => {
  const ci = text('.github/workflows/ci.yml');
  assert.match(ci, /^on:\n {2}pull_request:\n/m);
  assert.doesNotMatch(ci, /^ {2}push:/m);
  assert.equal(ci.match(/runs-on:/g).length, 1);
  assert.match(ci, /runs-on: ubuntu-latest\n/);
  assert.match(ci, /node-version: 22\n/);
  assert.match(ci, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}\n/);
  assert.match(ci, /run: npm run gate\n/);
});

test('the other Node versions and arm run on a schedule and do not block a pull request', () => {
  const extra = text('.github/workflows/ci-extended.yml');
  assert.match(extra, /schedule:\n/);
  assert.match(extra, /workflow_dispatch:\n/);
  assert.doesNotMatch(extra, /pull_request:/);
  assert.match(extra, /cron: '0 15 \* \* 1'/);
  assert.match(extra, /node: '22'\n\s+os: ubuntu-24\.04-arm/);
  assert.match(extra, /node: '24'\n\s+os: ubuntu-latest/);
  assert.match(extra, /node: '26'\n\s+os: ubuntu-24\.04-arm/);
  assert.doesNotMatch(extra, /node: '22'\n\s+os: ubuntu-latest/);
  assert.match(extra, /run: npm run gate\n/);
});

test('the tag workflow checks the version and the pack and does not run the gate', () => {
  const release = text('.github/workflows/release.yml');
  assert.match(release, /tags:\n\s+- v\*\n/);
  assert.match(release, /node scripts\/release-version\.mjs\n/);
  assert.match(release, /run: npm run pack:check\n/);
  assert.match(release, /npm publish --provenance --tag "\$tag"/);
  assert.match(release, /tag=latest\n/);
  assert.doesNotMatch(release, /npm run gate/);
  const guard = text('scripts/autopilot/guard.mjs');
  assert.match(guard, /fast-forward main to that commit/);
  assert.doesNotMatch(guard, /Create a merge commit/);
});

test('the release version check accepts this tree and rejects a different tag', async () => {
  const { tagFromRef, versionsMatch, evaluate } = await import('../../scripts/release-version.mjs');
  assert.equal(tagFromRef('refs/tags/v3.5.0'), '3.5.0');
  assert.equal(tagFromRef('refs/heads/main'), '');
  assert.equal(versionsMatch('3.5.0', '3.5.0', '3.5.0'), true);
  assert.equal(versionsMatch('3.5.0', '3.4.0', '3.5.0'), false);
  assert.equal(versionsMatch('', '3.5.0', '3.5.0'), false);
  assert.equal(evaluate(ROOT, 'refs/tags/v4.2.0'), '');
  assert.match(evaluate(ROOT, 'refs/tags/v9.9.9'), /release version check failed/);

  const ok = spawnSync(process.execPath, ['scripts/release-version.mjs'], {
    cwd: ROOT,
    env: { ...process.env, GITHUB_REF: 'refs/tags/v4.2.0' },
    encoding: 'utf8',
  });
  assert.equal(ok.status, 0, ok.stderr);

  const bad = spawnSync(process.execPath, ['scripts/release-version.mjs'], {
    cwd: ROOT,
    env: { ...process.env, GITHUB_REF: 'refs/tags/v9.9.9' },
    encoding: 'utf8',
  });
  assert.equal(bad.status, 1);
  assert.match(bad.stderr, /release version check failed/);
});
