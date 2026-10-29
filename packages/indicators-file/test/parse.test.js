'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseIndicators, loadIndicatorFile } = require('../src/index.js');

test('json, jsonl, and text lines become indicator rows', () => {
  const json = parseIndicators(
    JSON.stringify([
      { value: '203.0.113.9', type: 'ip', source: 'lab' },
      { value: 'Bad.Example', type: 'domain', source: 'lab', confidence: 0.5 },
    ]),
  );
  assert.strictEqual(json[0].value, '203.0.113.9');
  assert.strictEqual(json[1].value, 'bad.example');
  assert.strictEqual(json[1].confidence, 0.5);
  assert.strictEqual(json[1].expiresTs, null);

  const lines = parseIndicators(
    '# comment\nip 198.51.100.8 feed\n\n{"value":"pool.example","type":"domain"}\n',
    { source: 'feed', expiresTs: 50 },
  );
  assert.strictEqual(lines.length, 2);
  assert.deepStrictEqual(lines[0], {
    value: '198.51.100.8',
    type: 'ip',
    source: 'feed',
    confidence: 1,
    expiresTs: 50,
  });
  assert.strictEqual(lines[1].value, 'pool.example');
  assert.strictEqual(lines[1].expiresTs, 50);

  assert.throws(() => parseIndicators('{"__proto__":{"x":1}}'), /invalid/);
  assert.throws(
    () => parseIndicators('[{"value":"a.example","type":"domain","source":"s"}]', { max: 0 }),
    /cap/,
  );
  assert.throws(() => parseIndicators('nope'), /invalid/);
});

test('loadIndicatorFile reads a local file and does not contain a feed', () => {
  const file = path.join(os.tmpdir(), `hubvik-indicators-${process.pid}.txt`);
  fs.writeFileSync(file, 'domain vendor.example lab\n');
  try {
    const rows = loadIndicatorFile(file);
    assert.strictEqual(rows.length, 1);
    assert.strictEqual(rows[0].value, 'vendor.example');
  } finally {
    fs.unlinkSync(file);
  }
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'index.js'), 'utf8');
  assert.doesNotMatch(src, /https?:\/\//);
  assert.doesNotMatch(src, /child_process/);
});
