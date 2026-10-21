'use strict';

const { fromJSON } = require('../packages/core/src/engine/stats/minhash');
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
  const kind = Math.floor(next() * 6);
  if (kind === 0) return null;
  if (kind === 1) return { sig: 'ok' };
  if (kind === 2) return { sig: '%%%' };
  if (kind === 3) return { __proto__: { sig: 'x' } };
  if (kind === 4) return { constructor: { polluted: true }, sig: 'YQ==' };
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
  console.error('minhash fuzz polluted Object.prototype');
  process.exit(1);
}
if (rejected === 0) {
  console.error('minhash fuzz accepted every input');
  process.exit(1);
}
console.log(`minhash fuzz: ${N} inputs, ${rejected} rejected`);
