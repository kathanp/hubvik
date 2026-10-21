'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { mulberry32 } = require('../../../../test/fixtures/prng');
const { HubvikError } = require('../../src/errors');
const {
  createMinHash,
  add,
  jaccard,
  bands,
  toJSON,
  fromJSON,
} = require('../../src/engine/stats/minhash');

/** Fixed signature of camera, port:443, example.com. */
const KNOWN = [
  901246666, 2856283700, 748388718, 499760360, 312137385, 328959945, 2148370871, 355071426,
  339228963, 1737349992, 516951648, 994498265, 404040360, 1809675, 2311366906, 1838408798,
  2936633162, 1911183978, 929280177, 1378390127, 108779508, 603158716, 955649322, 1068263324,
  1089030540, 2374621674, 920498531, 17650749, 997825395, 843941845, 105649829, 1417999477,
  2341634898, 2168658517, 1679284366, 932367587, 399606069, 452723447, 1461691979, 403791239,
  89187485, 2139007255, 916132671, 1195621150, 1057180813, 1434519840, 1567821307, 3220470782,
  30874285, 2839930056, 946189156, 2856735352, 80600498, 3149700527, 2151849684, 1646807589,
  2024874319, 1446119875, 2090788781, 356600194, 2049867631, 1398241163, 1113463214, 2329879910,
];

/**
 * @param {Iterable<string>} tokens
 * @returns {{ sig: Uint32Array }}
 */
function sketch(tokens) {
  const state = createMinHash();
  for (const token of tokens) add(state, token);
  return state;
}

/**
 * @param {() => number} rng
 * @param {number} count
 * @param {Set<string>} used
 * @returns {string[]}
 */
function take(rng, count, used) {
  /** @type {string[]} */
  const out = [];
  while (out.length < count) {
    const token = `t${Math.floor(rng() * 100000)}`;
    if (used.has(token)) continue;
    used.add(token);
    out.push(token);
  }
  return out;
}

test('empty signature is 64 slots of 0xFFFFFFFF and a fixed set has a known answer', () => {
  const empty = createMinHash();
  assert.strictEqual(empty.sig.length, 64);
  assert.strictEqual(empty.sig.byteLength, 256);
  for (const slot of empty.sig) assert.strictEqual(slot, 0xffffffff);
  assert.strictEqual(jaccard(empty, empty), 1);

  const state = sketch(['camera', 'port:443', 'example.com']);
  assert.deepStrictEqual(Array.from(state.sig), KNOWN);
  assert.strictEqual(state.sig.byteLength, 256);

  const reversed = sketch(['example.com', 'port:443', 'camera']);
  assert.deepStrictEqual(reversed.sig, state.sig);
  const doubled = sketch(['camera', 'port:443', 'example.com', 'camera', 'port:443']);
  assert.deepStrictEqual(doubled.sig, state.sig);
});

test('identical sets estimate 1 and disjoint sets estimate near 0', () => {
  const tokens = ['a', 'b', 'c', 'port:22', 'port:443'];
  assert.strictEqual(jaccard(sketch(tokens), sketch(tokens.slice().reverse())), 1);

  const left = sketch(Array.from({ length: 20 }, (_, i) => `left-${i}`));
  const right = sketch(Array.from({ length: 20 }, (_, i) => `right-${i}`));
  assert.ok(jaccard(left, right) <= 0.05);
});

test('absolute Jaccard error is within 0.15 on at least 95% of 1,000 seeded pairs', () => {
  const rng = mulberry32(20261021);
  let within = 0;
  for (let i = 0; i < 1000; i++) {
    const mode = Math.floor(rng() * 5);
    /** @type {string[]} */
    let leftTokens;
    /** @type {string[]} */
    let rightTokens;
    /** @type {number} */
    let truth;
    if (mode === 0) {
      const used = new Set();
      leftTokens = take(rng, 5 + Math.floor(rng() * 30), used);
      rightTokens = leftTokens.slice();
      truth = 1;
    } else if (mode === 1) {
      const used = new Set();
      leftTokens = take(rng, 5 + Math.floor(rng() * 30), used);
      rightTokens = take(rng, 5 + Math.floor(rng() * 30), used);
      truth = 0;
    } else {
      const inter = 1 + Math.floor(rng() * 25);
      const onlyLeft = Math.floor(rng() * 25);
      const onlyRight = Math.floor(rng() * 25);
      const used = new Set();
      const shared = take(rng, inter, used);
      const leftOnly = take(rng, onlyLeft, used);
      const rightOnly = take(rng, onlyRight, used);
      leftTokens = shared.concat(leftOnly);
      rightTokens = shared.concat(rightOnly);
      truth = inter / (inter + onlyLeft + onlyRight);
    }
    const estimate = jaccard(sketch(leftTokens), sketch(rightTokens));
    if (truth === 1) assert.strictEqual(estimate, 1);
    if (truth === 0) assert.ok(estimate <= 0.05);
    if (Math.abs(estimate - truth) <= 0.15) within += 1;
  }
  assert.ok(within >= 950, `${within}/1000 pairs within 0.15`);
});

test('LSH banding is 16 bands of 4 rows and does not alias the signature', () => {
  const state = sketch(['camera', 'port:443', 'example.com']);
  const keys = bands(state);
  assert.strictEqual(keys.length, 16);
  for (let band = 0; band < 16; band++) {
    assert.strictEqual(keys[band].length, 4);
    for (let row = 0; row < 4; row++) {
      assert.strictEqual(keys[band][row], state.sig[band * 4 + row]);
    }
  }
  const before = state.sig[0];
  keys[0][0] = 1;
  assert.strictEqual(state.sig[0], before);
});

test('toJSON round-trips and fromJSON rejects unsafe or malformed input', () => {
  const state = sketch(['camera', 'port:443', 'example.com']);
  const saved = JSON.parse(JSON.stringify(toJSON(state)));
  const restored = fromJSON(saved);
  assert.deepStrictEqual(restored.sig, state.sig);
  assert.strictEqual(jaccard(restored, state), 1);
  assert.notStrictEqual(restored.sig, state.sig);

  assert.throws(() => fromJSON(null), /object/);
  assert.throws(() => fromJSON([]), /object/);
  assert.throws(() => fromJSON('nope'), /object/);
  assert.throws(
    () => fromJSON(JSON.parse('{"__proto__":{"x":1},"sig":"YQ=="}')),
    (err) => err instanceof HubvikError && /forbidden key/.test(err.message),
  );
  assert.throws(() => fromJSON({ constructor: { a: 1 }, sig: 'YQ==' }), /forbidden key/);
  assert.throws(() => fromJSON({ prototype: { a: 1 }, sig: 'YQ==' }), /forbidden key/);
  assert.throws(() => fromJSON({}), /base64/);
  assert.throws(() => fromJSON({ sig: '' }), /base64/);
  assert.throws(() => fromJSON({ sig: 'YQ==' }), /length/);
  assert.throws(() => add(createMinHash(), /** @type {any} */ (1)), /string/);
});
