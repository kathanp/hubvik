'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { checkFreeze, row06Ticked } = require('../../../scripts/autopilot/freeze.js');

const ROOT = path.join(__dirname, '..', '..', '..');

test('the current tree matches the freeze list', () => {
  assert.deepStrictEqual(checkFreeze({ root: ROOT, baseIds: null }), []);
});

test('an id that is not in the list fails while row 0.6 is open', () => {
  const problems = checkFreeze({ root: ROOT, ids: ['not-a-detector'], baseIds: null });
  assert.ok(problems.some((line) => line.includes('not-a-detector')));
});

test('growing the list without ticking row 0.6 fails', () => {
  const problems = checkFreeze({ root: ROOT, ids: [], baseIds: [] });
  assert.ok(problems.some((line) => line.includes('grew')));
});

test('a ticked row 0.6 allows an id that is not in the list', () => {
  const spec = '| **0.6** | scope | gate | [x] |\n';
  assert.strictEqual(row06Ticked(spec), true);
  assert.deepStrictEqual(
    checkFreeze({ root: ROOT, spec, ids: ['not-a-detector'], baseIds: null }),
    [],
  );
});
