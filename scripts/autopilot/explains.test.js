'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { liveExplainProblems } = require('./explains.js');

test('live explain check fails one bare detector and passes when each live file explains', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-explains-'));
  fs.writeFileSync(
    path.join(dir, 'bare.js'),
    "module.exports = { id: 'bare', meta: {}, check() { return { severity: 'low' }; } };\n",
  );
  fs.writeFileSync(
    path.join(dir, 'shade.js'),
    "module.exports = { id: 'shade', meta: { mode: 'shadow' } };\n",
  );
  const missing = liveExplainProblems(dir, require);
  assert.deepStrictEqual(missing.problems, ['bare live detector has no explain']);
  assert.strictEqual(missing.live, 1);
  assert.strictEqual(missing.explained, 0);
  fs.writeFileSync(
    path.join(dir, 'bare.js'),
    [
      'function explainMatch(spec) { return spec; }',
      'module.exports = {',
      "  id: 'bare',",
      '  meta: { explains: true },',
      '  check() {',
      '    return { explain: explainMatch({ observed: "a", matched: "b", source: "c" }) };',
      '  },',
      '};',
      '',
    ].join('\n'),
  );
  for (const key of Object.keys(require.cache)) {
    if (key.endsWith(`${path.sep}bare.js`)) delete require.cache[key];
  }
  const filled = liveExplainProblems(dir, require);
  assert.deepStrictEqual(filled.problems, []);
  assert.strictEqual(filled.explained, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});
