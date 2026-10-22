'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');
const { fmix32 } = require('./hash');

const TREES = 10;
const DEPTH = 8;
const NODES = (1 << DEPTH) - 1;
const DIMS = 8;

/**
 * Ten half-space trees of depth 8. Splits come from a seeded hash.
 * A point's score is the sum of the leaf masses it lands in. A small score is more unusual.
 * @param {number} seed
 * @returns {{ seed: number, mass: Uint32Array, lo: Float64Array, hi: Float64Array, seen: number }}
 */
function createForest(seed) {
  if (!Number.isInteger(seed) || seed < 0) {
    throw new HubvikError('HSTREE_SEED_IS_INVALID', 'hstree seed is invalid');
  }
  return {
    seed,
    mass: new Uint32Array(TREES * NODES),
    lo: new Float64Array(DIMS).fill(Infinity),
    hi: new Float64Array(DIMS).fill(-Infinity),
    seen: 0,
  };
}

/**
 * @param {any} state
 * @returns {void}
 */
function assertForest(state) {
  if (
    !state ||
    typeof state !== 'object' ||
    !(state.mass instanceof Uint32Array) ||
    state.mass.length !== TREES * NODES ||
    !(state.lo instanceof Float64Array) ||
    !(state.hi instanceof Float64Array)
  ) {
    throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
  }
}

/**
 * @param {number} seed
 * @param {number} tree
 * @param {number} node
 * @returns {number}
 */
function mix(seed, tree, node) {
  return fmix32(Math.imul(seed + 1, 0x9e3779b1) ^ Math.imul(tree + 1, 0x85ebca6b) ^ (node + 1));
}

/**
 * @param {{ seed: number, lo: Float64Array, hi: Float64Array }} state
 * @param {number} tree
 * @param {number} node
 * @returns {{ dim: number, split: number }}
 */
function splitOf(state, tree, node) {
  const hash = mix(state.seed, tree, node);
  const dim = hash % DIMS;
  const span = state.hi[dim] - state.lo[dim];
  const unit = (hash >>> 8) / 0x1000000;
  const split = span > 0 ? state.lo[dim] + unit * span : state.lo[dim];
  return { dim, split };
}

/**
 * @param {Float64Array | number[]} point
 * @returns {void}
 */
function assertPoint(point) {
  if (!point || point.length !== DIMS) {
    throw new HubvikError('HSTREE_POINT_IS_INVALID', 'hstree point is invalid');
  }
  for (let i = 0; i < DIMS; i += 1) {
    if (typeof point[i] !== 'number' || !Number.isFinite(point[i])) {
      throw new HubvikError('HSTREE_POINT_IS_INVALID', 'hstree point is invalid');
    }
  }
}

/**
 * Record one 8-dimensional window. The first 256 points set the split ranges.
 * @param {ReturnType<typeof createForest>} state
 * @param {number[]} point
 * @returns {number}
 */
function push(state, point) {
  assertForest(state);
  assertPoint(point);
  if (state.seen < 256) {
    for (let i = 0; i < DIMS; i += 1) {
      if (point[i] < state.lo[i]) state.lo[i] = point[i];
      if (point[i] > state.hi[i]) state.hi[i] = point[i];
    }
  }
  state.seen += 1;
  let score = 0;
  for (let tree = 0; tree < TREES; tree += 1) {
    let node = 0;
    for (let depth = 0; depth < DEPTH - 1; depth += 1) {
      state.mass[tree * NODES + node] += 1;
      const split = splitOf(state, tree, node);
      node = node * 2 + 1 + (point[split.dim] >= split.split ? 1 : 0);
    }
    const leaf = tree * NODES + node;
    state.mass[leaf] += 1;
    score += state.mass[leaf];
  }
  return score;
}

/**
 * Leaf-mass sum for one point. Does not change the forest.
 * @param {ReturnType<typeof createForest>} state
 * @param {number[]} point
 * @returns {number}
 */
function score(state, point) {
  assertForest(state);
  assertPoint(point);
  let total = 0;
  for (let tree = 0; tree < TREES; tree += 1) {
    let node = 0;
    for (let depth = 0; depth < DEPTH - 1; depth += 1) {
      const split = splitOf(state, tree, node);
      node = node * 2 + 1 + (point[split.dim] >= split.split ? 1 : 0);
    }
    total += state.mass[tree * NODES + node];
  }
  return total;
}

/**
 * Zero every mass counter and keep the split ranges.
 * @param {ReturnType<typeof createForest>} state
 * @returns {void}
 */
function refresh(state) {
  assertForest(state);
  state.mass.fill(0);
}

/**
 * @param {ReturnType<typeof createForest>} state
 * @returns {{ seed: number, seen: number, lo: number[], hi: number[], mass: string }}
 */
function toJSON(state) {
  assertForest(state);
  return {
    seed: state.seed,
    seen: state.seen,
    lo: Array.from(state.lo),
    hi: Array.from(state.hi),
    mass: Buffer.from(state.mass.buffer, state.mass.byteOffset, state.mass.byteLength).toString(
      'base64',
    ),
  };
}

/**
 * @param {unknown} raw
 * @returns {ReturnType<typeof createForest>}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
  }
  assertSafeKeys(raw, 'hstree');
  const row = /** @type {any} */ (raw);
  if (!Number.isInteger(row.seed) || row.seed < 0) {
    throw new HubvikError('HSTREE_SEED_IS_INVALID', 'hstree seed is invalid');
  }
  const state = createForest(row.seed);
  if (!Number.isInteger(row.seen) || row.seen < 0) {
    throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
  }
  if (
    !Array.isArray(row.lo) ||
    !Array.isArray(row.hi) ||
    row.lo.length !== DIMS ||
    row.hi.length !== DIMS
  ) {
    throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
  }
  for (let i = 0; i < DIMS; i += 1) {
    if (typeof row.lo[i] !== 'number' || typeof row.hi[i] !== 'number') {
      throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
    }
    state.lo[i] = row.lo[i];
    state.hi[i] = row.hi[i];
  }
  if (typeof row.mass !== 'string') {
    throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
  }
  const bytes = Buffer.from(row.mass, 'base64');
  if (bytes.length !== state.mass.byteLength) {
    throw new HubvikError('HSTREE_STATE_MUST_BE_AN_OBJECT', 'hstree state must be an object');
  }
  new Uint8Array(state.mass.buffer).set(bytes);
  state.seen = row.seen;
  return state;
}

module.exports = { TREES, DEPTH, DIMS, createForest, push, score, refresh, toJSON, fromJSON };
