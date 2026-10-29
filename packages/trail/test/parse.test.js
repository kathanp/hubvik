'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseTrail, loadTrailFile } = require('../src/index.js');

test('a trail file becomes indicator rows and does not fetch', () => {
  const rows = parseTrail('# comment\n203.0.113.9\n\nEvil.Example:443\n198.51.100.0/24\n');
  assert.deepStrictEqual(rows, [
    { value: '203.0.113.9', type: 'ip', source: 'trail', confidence: 1, expiresTs: null },
    { value: 'evil.example', type: 'domain', source: 'trail', confidence: 1, expiresTs: null },
    { value: '198.51.100.0/24', type: 'cidr', source: 'trail', confidence: 1, expiresTs: null },
  ]);
  assert.throws(() => parseTrail('not a host'), /invalid/);
  assert.throws(() => parseTrail('203.0.113.9\n198.51.100.8\n', { max: 1 }), /cap/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-trail-'));
  const file = path.join(dir, 'trail.txt');
  fs.writeFileSync(file, '2001:db8::1\n');
  const loaded = loadTrailFile(file, { source: 'lab' });
  assert.strictEqual(loaded[0].type, 'ip');
  assert.strictEqual(loaded[0].value, '2001:db8::1');
  const src = fs.readFileSync(path.join(__dirname, '../src/index.js'), 'utf8');
  assert.doesNotMatch(src, /child_process|https?:\/\//);
});
