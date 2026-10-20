'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const { readdirSync } = require('node:fs');

test('examples 01 through 08 run', () => {
  const files = readdirSync('examples')
    .filter((name) => /^\d\d-/.test(name) && name.endsWith('.js'))
    .sort();
  assert.deepStrictEqual(files, [
    '01-feed.js',
    '02-baseline.js',
    '03-checkpoint.js',
    '04-shadow.js',
    '05-timezone.js',
    '06-redact.js',
    '07-rules.js',
    '08-summary.js',
  ]);
  for (const name of files) {
    execFileSync(process.execPath, [`examples/${name}`], { encoding: 'utf8' });
  }
});
