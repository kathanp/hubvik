'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { parseDecisions, loadDecisionsFile } = require('../src/index.js');

test('a decisions file becomes indicators and does not ban', () => {
  const rows = parseDecisions(
    JSON.stringify([
      {
        scope: 'Ip',
        value: '203.0.113.9',
        duration: '4h',
        scenario: 'lab/ssh',
        type: 'ban',
      },
    ]),
    { now: 1_000_000 },
  );
  assert.deepStrictEqual(rows, [
    {
      value: '203.0.113.9',
      type: 'ip',
      source: 'lab/ssh',
      confidence: 1,
      expiresTs: 1_000_000 + 4 * 3_600_000,
    },
  ]);
  assert.strictEqual(Object.hasOwn(rows[0], 'ban'), false);
  const domain = parseDecisions('{"scope":"Domain","value":"Bad.Example","scenario":"lab"}\n');
  assert.strictEqual(domain[0].type, 'domain');
  assert.strictEqual(domain[0].value, 'bad.example');
  assert.strictEqual(domain[0].expiresTs, null);
  assert.throws(() => parseDecisions('{"__proto__":{"x":1}}'), /invalid/);
  assert.throws(
    () => parseDecisions('[{"scope":"Ip","value":"203.0.113.9","duration":"4h"}]'),
    /now/,
  );
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-decisions-'));
  const file = path.join(dir, 'decisions.json');
  fs.writeFileSync(
    file,
    JSON.stringify([{ scope: 'Range', value: '198.51.100.0/24', scenario: 'lab' }]),
  );
  assert.strictEqual(loadDecisionsFile(file)[0].type, 'cidr');
  const src = fs.readFileSync(path.join(__dirname, '../src/index.js'), 'utf8');
  assert.doesNotMatch(src, /child_process|nft|https?:\/\//);
});
