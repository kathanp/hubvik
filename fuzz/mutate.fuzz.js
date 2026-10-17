'use strict';

const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;

/**
 * @param {any} value
 * @returns {any}
 */
function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

/**
 * @param {any} value
 * @param {object[]} out
 */
function nodesOf(value, out) {
  if (!value || typeof value !== 'object') return;
  out.push(value);
  const children = Array.isArray(value) ? value : Object.values(value);
  for (const child of children) nodesOf(child, out);
}

/**
 * @param {any} root
 * @param {() => number} rng
 */
function mutate(root, rng) {
  /** @type {object[]} */
  const nodes = [];
  nodesOf(root, nodes);
  const node = nodes[Math.floor(rng() * nodes.length)];
  const keys = Object.keys(node);
  const kind = Math.floor(rng() * 6);
  if (kind === 0) {
    Object.assign(node, JSON.parse(`{"__proto__":{"x":${Math.floor(rng() * 10)}}}`));
    return;
  }
  if (keys.length === 0) {
    node.extra = Math.floor(rng() * 5);
    return;
  }
  const key = keys[Math.floor(rng() * keys.length)];
  if (kind === 1) {
    delete node[key];
    return;
  }
  if (kind === 2) {
    node[key] = null;
    return;
  }
  if (kind === 3) {
    node[key] = typeof node[key] === 'number' ? node[key] + 1 : 1;
    return;
  }
  if (kind === 4) {
    node[key] = typeof node[key] === 'string' ? `${node[key]}x` : 'x';
    return;
  }
  node[key] = node[key] === true ? false : true;
}

/**
 * @param {string} label
 * @param {(engine: import('../packages/core/src/index.js').Engine, value: any) => void} apply
 * @param {any} valid
 * @param {number} seed
 */
function run(label, apply, valid, seed) {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  apply(engine, clone(valid));
  const rng = mulberry32(seed);
  let accepted = 0;
  let rejected = 0;
  for (let i = 0; i < N; i++) {
    const before = engine.stats().devices;
    const sample = clone(valid);
    mutate(sample, rng);
    try {
      apply(engine, sample);
    } catch (err) {
      if (engine.stats().devices !== before) {
        throw new Error(`${label} mutation changed state`, { cause: err });
      }
      if (Object.hasOwn(Object.prototype, 'x')) {
        throw new Error('prototype polluted', { cause: err });
      }
      if (!(err instanceof Error)) throw err;
      rejected += 1;
      continue;
    }
    if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
    try {
      engine.feed({ device: 'd', dst: 'still.example', bytes: 1, ts: 10_000 + i });
    } catch (err) {
      throw new Error(`${label} accepted a value that broke feed`, { cause: err });
    }
    accepted += 1;
  }
  console.log(`${label} mutation fuzz: ${N} inputs, ${accepted} accepted, ${rejected} rejected`);
}

const source = createEngine({ learnMs: 0, tiers: ['T0'] });
source.feed({ device: 'd', dst: 'a.example', bytes: 100, ts: 0 });
source.feed({ device: 'd', dst: 'b.example', bytes: 50, ts: 60_000 });
const baseline = source.exportBaseline({ createdAt: 1 });
const checkpoint = source.checkpoint({ createdAt: 1 });

run('baseline', (engine, value) => engine.importBaseline(value), baseline, 20261020);
run('checkpoint', (engine, value) => engine.restore(value), checkpoint, 20261021);
