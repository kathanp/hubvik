'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mulberry32 } = require('../../../../test/fixtures/prng');
const { HubvikError } = require('../../src/errors');
const {
  BITS,
  K,
  createBloom,
  add,
  has,
  toJSON,
  fromJSON,
} = require('../../src/engine/stats/bloom');

test('a bloom filter keeps inserted names and stays near the theoretical false-positive rate', () => {
  const filter = createBloom();
  const rng = mulberry32(7);
  const inserted = 50_000;
  for (let i = 0; i < inserted; i += 1) add(filter, `fam-${rng().toString(16)}-${i}`);
  add(filter, 'example.com');
  assert.equal(has(filter, 'example.com'), true);
  assert.equal(has(filter, 'missing.example'), false);
  let hits = 0;
  const queries = 50_000;
  for (let i = 0; i < queries; i += 1) {
    if (has(filter, `absent-${i}-${rng().toString(16)}`)) hits += 1;
  }
  const theoretical = (1 - Math.exp((-K * (inserted + 1)) / BITS)) ** K;
  assert.ok(hits / queries <= 1.5 * theoretical, `${hits / queries} vs ${theoretical}`);
  const copy = fromJSON(toJSON(filter));
  assert.equal(has(copy, 'example.com'), true);
});

test('bloom fromJSON rejects garbage', () => {
  assert.throws(
    () => fromJSON(null),
    (err) => err instanceof HubvikError,
  );
  assert.throws(
    () => fromJSON({ __proto__: { bits: 'x' } }),
    (err) => err instanceof HubvikError,
  );
  assert.throws(
    () => add(createBloom(), ''),
    (err) => err instanceof HubvikError,
  );
});
