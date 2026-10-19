'use strict';

const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;
const rng = mulberry32(20261019);
let rejected = 0;

/**
 * @param {() => number} next
 */
function garbage(next) {
  const kind = Math.floor(next() * 6);
  if (kind === 0) return null;
  if (kind === 1) return { id: 'ok', severity: 'high', on: 'flow', window: '1m' };
  if (kind === 2)
    return {
      id: 'bad id',
      severity: 'high',
      on: 'nope',
      window: '2m',
      where: { a: { regex: '.*' } },
    };
  if (kind === 3)
    return {
      id: 'seq',
      severity: 'low',
      within: '10m',
      by: 'srcIp',
      sequence: [{ on: 'flow' }, { on: 'dns' }],
    };
  if (kind === 4) return { __proto__: { id: 'x' } };
  return [];
}

const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
for (let i = 0; i < N; i += 1) {
  const count = 1 + Math.floor(rng() * 3);
  /** @type {any[]} */
  const rules = [];
  for (let j = 0; j < count; j += 1) rules.push(garbage(rng));
  try {
    engine.loadRules(rules);
  } catch {
    rejected += 1;
    continue;
  }
  engine.loadRules([]);
}

if (rejected === 0) {
  console.error('rules fuzz accepted every input');
  process.exit(1);
}
console.log(`rules fuzz: ${N} inputs, ${rejected} rejected`);
