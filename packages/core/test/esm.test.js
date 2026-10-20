'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const { pathToFileURL } = require('node:url');

test('the ESM entry exports the same engine constructors', async () => {
  const mod = await import(pathToFileURL(require.resolve('../src/index.mjs')).href);
  assert.strictEqual(typeof mod.createEngine, 'function');
  assert.strictEqual(typeof mod.createShardedEngine, 'function');
  const engine = mod.createEngine({ learnMs: 0 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  assert.strictEqual(engine.stats().devices, 1);
});

test('publint-lite accepts every public package', () => {
  const out = execFileSync(process.execPath, ['scripts/publint-lite.mjs'], { encoding: 'utf8' });
  assert.match(out, /publint-lite: ok/);
});
