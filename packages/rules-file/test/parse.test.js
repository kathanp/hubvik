'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseRules, loadRulesFile } = require('../src/index.js');

test('a rules file returns data rules and rejects a regular expression', () => {
  const rule = {
    id: 'telnet',
    on: 'flow',
    severity: 'high',
    where: { dstPort: { eq: 23 } },
  };
  const rows = parseRules(JSON.stringify([rule]));
  assert.deepStrictEqual(rows, [rule]);
  assert.throws(
    () => parseRules(JSON.stringify([{ id: 'bad', where: { dst: { regex: '.*' } } }])),
    /invalid/,
  );
  assert.throws(() => parseRules('{"__proto__":{}}'), /invalid/);
  assert.throws(() => parseRules('[1,2]', { max: 1 }), /cap/);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-rules-'));
  const file = path.join(dir, 'rules.json');
  fs.writeFileSync(file, JSON.stringify([rule]));
  assert.strictEqual(loadRulesFile(file)[0].id, 'telnet');
  const src = fs.readFileSync(path.join(__dirname, '../src/index.js'), 'utf8');
  assert.doesNotMatch(src, /child_process|eval\(|new Function/);
});
