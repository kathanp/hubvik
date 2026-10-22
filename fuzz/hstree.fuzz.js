'use strict';

const { fromJSON } = require('../packages/core/src/engine/stats/hstree');
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
  if (kind === 1) return { seed: -1, seen: 0, lo: [], hi: [], mass: '' };
  if (kind === 2) return { seed: 1, seen: 1, lo: [1], hi: [1], mass: '%%%' };
  if (kind === 3) return { __proto__: { seed: 1 } };
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
  console.error('hstree fuzz polluted Object.prototype');
  process.exit(1);
}
if (rejected !== N) {
  console.error(`hstree fuzz rejected ${rejected} of ${N}`);
  process.exit(1);
}
console.log(`hstree fuzz: ${N} inputs, ${rejected} rejected`);
