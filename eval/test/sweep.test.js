'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { main } = require('../cli.js');
const { loadCached } = require('../cache.js');
const { fpRisesWithThreshold } = require('../sweep.js');

const ROOT = path.join(__dirname, '..', '..');
const DETECTORS = path.join(ROOT, 'packages', 'core', 'src', 'detectors');

/**
 * @param {string} dir
 * @returns {string}
 */
function hashDetectors(dir) {
  const hash = crypto.createHash('sha256');
  for (const name of fs.readdirSync(dir).sort()) {
    if (!name.endsWith('.js')) continue;
    hash.update(name);
    hash.update(fs.readFileSync(path.join(dir, name)));
  }
  return hash.digest('hex');
}

test('vertical-scan.minPorts=5:30:5 writes six synthetic points and leaves core untouched', () => {
  const before = hashDetectors(DETECTORS);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-sweep-'));
  const cache = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-cache-'));
  const result = main(['--sweep', 'vertical-scan.minPorts=5:30:5', '--cost', 'fp=1,miss=20'], {
    outDir: dir,
    cacheDir: cache,
    quiet: true,
  });
  assert.strictEqual(result.dataset, 'synthetic');
  assert.strictEqual(result.points.length, 6);
  assert.deepStrictEqual(
    result.points.map((point) => point.value),
    [5, 10, 15, 20, 25, 30],
  );
  const base = path.join(dir, 'sweep', 'vertical-scan-minPorts');
  const json = JSON.parse(fs.readFileSync(`${base}.json`, 'utf8'));
  const md = fs.readFileSync(`${base}.md`, 'utf8');
  assert.strictEqual(json.points.length, 6);
  assert.strictEqual(json.dataset, 'synthetic');
  assert.match(json.points[0].detection, /Wilson/);
  assert.match(json.points[0].fpPerDeviceDayWilson, /Wilson|no rate/);
  assert.ok('precision' in json.points[0]);
  assert.ok('recall' in json.points[0]);
  assert.match(md, /Wilson/);
  assert.match(md, /precision/);
  assert.ok(json.proposal);
  assert.strictEqual(json.proposal.defaultUnchanged, true);
  assert.match(json.proposal.text, /The default is unchanged/);
  assert.strictEqual(json.proposal.fp, 1);
  assert.strictEqual(json.proposal.miss, 20);
  assert.ok(result.points.some((point) => point.value === json.proposal.value));
  assert.strictEqual(hashDetectors(DETECTORS), before);
  assert.ok(fs.readdirSync(cache).some((name) => name.endsWith('.json')));
  assert.strictEqual(typeof result.fpRisesWithThreshold, 'boolean');
});

test('a rising false-positive curve is flagged, and blocked trees are refused', () => {
  assert.strictEqual(
    fpRisesWithThreshold([
      { value: 5, fpPerDeviceDay: 0.1 },
      { value: 10, fpPerDeviceDay: 0.4 },
    ]),
    true,
  );
  assert.strictEqual(
    fpRisesWithThreshold([
      { value: 5, fpPerDeviceDay: 0.4 },
      { value: 10, fpPerDeviceDay: 0.1 },
    ]),
    false,
  );
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-sweep-block-'));
  assert.throws(
    () =>
      main(
        [
          '--sweep',
          'vertical-scan.minPorts=5:30:5',
          '--zeek-logs',
          path.join(__dirname, '..', 'evasion'),
        ],
        { outDir: dir, quiet: true },
      ),
    /never run/,
  );
  assert.throws(
    () =>
      main(
        [
          '--sweep',
          'vertical-scan.minPorts=5:30:5',
          '--zeek-logs',
          path.join(__dirname, '..', 'adversary'),
        ],
        { outDir: dir, quiet: true },
      ),
    /never run/,
  );
  assert.throws(
    () => main(['--sweep', 'vertical-scan.minPorts=1:51:1'], { outDir: dir, quiet: true }),
    /50 points/,
  );
});

test('parsed events are read from the cache on the second call', () => {
  const cache = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-cache-unit-'));
  const source = path.join(__dirname, '..', 'fixtures');
  let calls = 0;
  const loader = () => {
    calls += 1;
    return { rows: [{ device: 'cam', ts: 0 }], tiers: ['T1'], dataset: 'synthetic' };
  };
  const first = loadCached(cache, 'unit', source, loader);
  const second = loadCached(cache, 'unit', source, loader);
  assert.strictEqual(calls, 1);
  assert.deepStrictEqual(second, first);
});
