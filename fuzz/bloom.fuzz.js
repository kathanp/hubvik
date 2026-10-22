'use strict';

const { fromJSON } = require('../packages/core/src/engine/stats/bloom');
const { HubvikError } = require('../packages/core/src/errors');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;
const rng = mulberry32(20261021);
let rejected = 0;

/**
 * @param {() => number} next
 * @returns {unknown}
 */
function garbage(next) {
  const kind = Math.floor(next() * 5);
  if (kind === 0) return null;
  if (kind === 1) return { bits: 1 };
  if (kind === 2) return { bits: '%%%' };
  if (kind === 3) return { __proto__: { bits: 'x' } };
  return [];
}

for (let i = 0; i < N; i += 1) {
  try {
    fromJSON(garbage(rng));
  } catch (err) {
    if (!(err instanceof HubvikError)) throw err;
    rejected += 1;
  }
}

if (Object.hasOwn(Object.prototype, 'polluted')) {
  console.error('bloom fuzz polluted Object.prototype');
  process.exit(1);
}
if (rejected !== N) {
  console.error(`bloom fuzz rejected ${rejected} of ${N}`);
  process.exit(1);
}
console.log(`bloom fuzz: ${N} inputs, ${rejected} rejected`);
