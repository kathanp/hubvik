'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

/**
 * @param {import('../src/index.js').Engine} engine
 * @param {number} start
 * @param {number} hosts
 * @param {number} port
 */
function scan(engine, start, hosts, port) {
  for (let i = 0; i < hosts; i++) {
    engine.feed({
      type: 'flow',
      device: 'd',
      ts: start + i,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: `203.0.113.${i}`,
      dstPort: port,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 20,
    });
  }
}

test('the same scan keeps one fingerprint when the host count changes', () => {
  const engine = createEngine({ learnMs: 10 * 60_000, tiers: ['T1'] });
  /** @type {any[]} */
  const hits = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'horizontal-scan') hits.push(item);
  });
  scan(engine, 0, 25, 23);
  scan(engine, 60_000, 1, 23);
  engine.lock('d');
  scan(engine, 120_000, 76, 23);
  assert.strictEqual(hits.length, 2);
  assert.notStrictEqual(hits[0].actual, hits[1].actual);
  assert.match(hits[0].actual, /port 23/);
  assert.match(hits[1].actual, /port 23/);
  assert.strictEqual(hits[0].fingerprint, hits[1].fingerprint);
});
