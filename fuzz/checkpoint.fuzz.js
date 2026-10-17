'use strict';

const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;

/**
 * @param {() => number} rng
 * @param {number} i
 */
function junk(rng, i) {
  const kind = Math.floor(rng() * 4);
  if (kind === 0) return null;
  if (kind === 1) return { version: 2, devices: {}, scratch: { [`nope-${i % 7}`]: {} } };
  if (kind === 2) return [];
  return JSON.parse(`{"__proto__":{"x":${i}},"version":2,"devices":{},"scratch":{}}`);
}

const engine = createEngine({ learnMs: 0 });
engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
const rng = mulberry32(20261019);
let rejected = 0;
for (let i = 0; i < N; i++) {
  const before = engine.stats().devices;
  try {
    engine.restore(junk(rng, i));
  } catch (err) {
    if (engine.stats().devices !== before) {
      throw new Error('restore changed state', { cause: err });
    }
    if (!(err instanceof Error)) throw err;
    rejected += 1;
  }
}
engine.feed({ device: 'd', dst: 'still.example', bytes: 1, ts: 1_000 });
if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
console.log(`checkpoint fuzz: ${N} inputs, ${rejected} rejected`);
