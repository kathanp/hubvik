'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { HubvikError } = require('../src/index.js');

const SRC = path.join(__dirname, '..', 'src');
const DOC = path.join(__dirname, '..', '..', '..', 'docs', 'ERRORS.md');

/**
 * @param {string} dir
 * @param {string[]} out
 */
function walk(dir, out) {
  for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name);
    if (fs.statSync(file).isDirectory()) walk(file, out);
    else if (name.endsWith('.js')) out.push(file);
  }
}

test('HubvikError keeps a stable code', () => {
  const err = new HubvikError('DEVICE_ID_IS_INVALID', 'device id is invalid');
  assert.ok(err instanceof Error);
  assert.strictEqual(err.name, 'HubvikError');
  assert.strictEqual(err.code, 'DEVICE_ID_IS_INVALID');
  assert.strictEqual(err.message, 'device id is invalid');
});

test('every thrown code is documented, and the document has no extra codes', () => {
  /** @type {Set<string>} */
  const used = new Set();
  const files = [];
  walk(SRC, files);
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;
      assert.ok(
        !/throw new (Error|TypeError|RangeError)\(/.test(line),
        `${file} still throws a bare error`,
      );
    }
    for (const match of text.matchAll(/HubvikError\(\s*'([A-Z0-9_]+)'/g)) used.add(match[1]);
  }
  const doc = fs.readFileSync(DOC, 'utf8');
  /** @type {Set<string>} */
  const listed = new Set();
  for (const match of doc.matchAll(/^## ([A-Z0-9_]+)$/gm)) listed.add(match[1]);
  for (const code of used) assert.ok(listed.has(code), `missing ${code} in ERRORS.md`);
  for (const code of listed) assert.ok(used.has(code), `ERRORS.md lists unused ${code}`);
  for (const code of listed) {
    const section = doc.split(`## ${code}`)[1].split('\n## ')[0];
    assert.match(section, /Cause:/, code);
    assert.match(section, /Fix:/, code);
  }
});
