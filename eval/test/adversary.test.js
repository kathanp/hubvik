'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { mulberry32 } = require('../../test/fixtures/prng.js');
const { runAdversary } = require('../adversary/generate.js');
const published = require('../adversary/params.js');
const holdout = require('../adversary-holdout/params.js');

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

test('adversary.md names four goals measured by an engine run', () => {
  const before = hashDetectors(DETECTORS);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-adversary-'));
  const file = path.join(dir, 'adversary.md');
  const result = runAdversary({ outPath: file });
  const text = fs.readFileSync(file, 'utf8');
  assert.strictEqual(result.goals.length, 4);
  assert.ok(result.families.length > 0);
  assert.ok(result.hours.length > 0);
  assert.equal(typeof result.ja4, 'string');
  assert.match(text, /alerts: not measured, G2 option not on/);
  assert.match(text, /white-box blind spot/);
  const names = [
    'exfiltrate 500 MB in 7 days',
    'scan 1,000 LAN or WAN hosts in 7 days',
    'keep a C2 beacon for 7 days',
    'write one OT setpoint outside its learned range',
  ];
  assert.deepStrictEqual(
    result.goals.map((goal) => goal.name),
    names,
  );
  for (const goal of result.goals) {
    assert.strictEqual(goal.measured, true);
    assert.strictEqual(typeof goal.reached, 'boolean');
    assert.ok(Array.isArray(goal.anomalies));
    const line = text.split('\n').find((row) => row.startsWith(`- ${goal.name}:`));
    assert.ok(line);
    if (goal.reached) assert.match(line, /: reached\b/);
    else assert.match(line, /: not reached\b/);
  }
  assert.strictEqual(hashDetectors(DETECTORS), before);
});

test('holdout parameters use another seed and other magnitudes', () => {
  assert.notStrictEqual(holdout.SEED, published.SEED);
  assert.notStrictEqual(mulberry32(holdout.SEED)(), mulberry32(published.SEED)());
  assert.notStrictEqual(holdout.EXFIL_BYTES, published.EXFIL_BYTES);
  assert.notStrictEqual(holdout.SCAN_HOSTS, published.SCAN_HOSTS);
  assert.notStrictEqual(holdout.BEACON_DAYS, published.BEACON_DAYS);
  assert.notStrictEqual(holdout.SPAN_DAYS, published.SPAN_DAYS);
  assert.notStrictEqual(holdout.OT_OFFSET, published.OT_OFFSET);
  assert.notStrictEqual(holdout.RATE, published.RATE);
  assert.notStrictEqual(holdout.LEARN_BYTES, published.LEARN_BYTES);
  assert.notDeepStrictEqual(holdout.ACTIVE_HOURS, published.ACTIVE_HOURS);
  assert.notStrictEqual(holdout.JA4, published.JA4);
  assert.notStrictEqual(holdout.BEACON_IP, published.BEACON_IP);
});
