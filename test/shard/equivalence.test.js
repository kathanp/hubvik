'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine } = require('../../packages/core/src/index.js');
const { capture } = require('../diff/corpus');

/**
 * @param {(opts?: object) => any} factory
 */
function run(factory) {
  /** @type {string[][]} */
  const live = [];
  /** @type {string[][]} */
  const shadow = [];
  const out = capture((opts) => {
    const engine = factory(opts);
    /** @type {string[]} */
    const liveRows = [];
    /** @type {string[]} */
    const shadowRows = [];
    engine.on('anomaly', (/** @type {any} */ item) => {
      liveRows.push(`${item.fingerprint}\t${item.ts}\t${item.severity}`);
    });
    engine.on('shadow-anomaly', (/** @type {any} */ item) => {
      shadowRows.push(`${item.fingerprint}\t${item.ts}\t${item.severity}`);
    });
    live.push(liveRows);
    shadow.push(shadowRows);
    return engine;
  });
  return { out, live, shadow };
}

/**
 * @param {string[]} rows
 * @returns {string[]}
 */
function multiset(rows) {
  return rows.slice().sort();
}

test('four inline shards match one engine on the benign matrix and every replay', () => {
  const single = run(createEngine);
  const split = run((opts) => createShardedEngine({ ...opts, shards: 4, inline: true }));
  const names = Object.keys(single.out);
  assert.deepStrictEqual(Object.keys(split.out), names);
  assert.strictEqual(split.live.length, single.live.length);
  for (let i = 0; i < names.length; i += 1) {
    const name = names[i];
    const left = single.out[name];
    const right = split.out[name];
    assert.deepStrictEqual(multiset(split.live[i]), multiset(single.live[i]), `${name} anomalies`);
    assert.deepStrictEqual(multiset(split.shadow[i]), multiset(single.shadow[i]), `${name} shadow`);
    assert.deepStrictEqual(right.baseline, left.baseline, `${name} baseline`);
  }
});
