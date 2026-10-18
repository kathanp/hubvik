'use strict';

const { mulberry32 } = require('../test/fixtures/prng');
const welford = require('../packages/core/src/engine/stats/welford');
const ewma = require('../packages/core/src/engine/stats/ewma');
const p2 = require('../packages/core/src/engine/stats/p2');
const hll = require('../packages/core/src/engine/stats/hll');
const cms = require('../packages/core/src/engine/stats/cms');
const cusum = require('../packages/core/src/engine/stats/cusum');
const pagehinkley = require('../packages/core/src/engine/stats/pagehinkley');

const N = 100_000;
const rng = mulberry32(20261018);

/**
 * @returns {unknown}
 */
function junk() {
  const kind = Math.floor(rng() * 8);
  if (kind === 0) return null;
  if (kind === 1) return [];
  if (kind === 2) return { __proto__: { polluted: true } };
  if (kind === 3) return { count: 'nope' };
  if (kind === 4) return { count: -1, mean: 0, m2: 0, min: 0, max: 1 };
  if (kind === 5) return { alpha: 2, mean: NaN, variance: -1, count: 1.5 };
  if (kind === 6) return { p: 1, count: 0, markers: '%%%' };
  return { constructor: { polluted: true }, table: 'YQ==' };
}

const readers = [
  welford.fromJSON,
  ewma.fromJSON,
  p2.fromJSON,
  hll.fromJSON,
  cms.fromJSON,
  cusum.fromJSON,
  pagehinkley.fromJSON,
];

let rejected = 0;
for (let i = 0; i < N; i++) {
  const read = readers[i % readers.length];
  try {
    const value = read(junk());
    read(JSON.parse(JSON.stringify(value)));
  } catch (err) {
    if (!(err instanceof Error)) throw err;
    rejected += 1;
  }
}
if (Object.hasOwn(Object.prototype, 'polluted')) throw new Error('prototype polluted');
console.log(`stats fuzz: ${N} inputs, ${rejected} rejected`);
