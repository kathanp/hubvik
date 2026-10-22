'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mulberry32 } = require('../../../../test/fixtures/prng');
const { HubvikError } = require('../../src/errors');
const {
  DIMS,
  createForest,
  push,
  score,
  toJSON,
  fromJSON,
} = require('../../src/engine/stats/hstree');

/**
 * @param {() => number} rng
 * @returns {number}
 */
function gaussian(rng) {
  const u = Math.max(rng(), 1e-12);
  const v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}

/**
 * @param {() => number} rng
 * @param {number} shift
 * @returns {number[]}
 */
function point(rng, shift) {
  const row = [];
  for (let i = 0; i < DIMS; i += 1) row.push(gaussian(rng) + shift);
  return row;
}

test('half-space trees separate a seeded gaussian from injected outliers', () => {
  const rng = mulberry32(11);
  const forest = createForest(7);
  for (let i = 0; i < 4_000; i += 1) push(forest, point(rng, 0));
  /** @type {{ score: number, outlier: number }[]} */
  const rows = [];
  for (let i = 0; i < 400; i += 1) rows.push({ score: score(forest, point(rng, 0)), outlier: 0 });
  for (let i = 0; i < 40; i += 1) rows.push({ score: score(forest, point(rng, 6)), outlier: 1 });
  rows.sort((a, b) => a.score - b.score);
  let rank = 0;
  let normalSeen = 0;
  const normals = rows.filter((row) => row.outlier === 0).length;
  for (const row of rows) {
    if (row.outlier === 1) rank += normals - normalSeen;
    else normalSeen += 1;
  }
  const auc = rank / (40 * normals);
  assert.ok(auc >= 0.9, String(auc));
  const copy = fromJSON(toJSON(forest));
  assert.equal(score(copy, point(mulberry32(3), 0)), score(forest, point(mulberry32(3), 0)));
});

test('hstree fromJSON rejects garbage', () => {
  assert.throws(
    () => fromJSON(null),
    (err) => err instanceof HubvikError,
  );
  assert.throws(
    () => push(createForest(1), [1]),
    (err) => err instanceof HubvikError,
  );
  assert.throws(
    () => createForest(-1),
    (err) => err instanceof HubvikError,
  );
});
