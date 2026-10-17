'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {string} srcIp
 */
function ra(srcIp) {
  return {
    type: 'ra',
    device: 'd',
    ts: 0,
    srcMac: 'aa:bb:cc:dd:ee:01',
    srcIp,
    prefixes: [],
    routerLifetime: 1800,
  };
}

test('an allowed router list fires only for a router that is not on it', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T4'],
    routers: ['fe80::1'],
  });
  const hits = [];
  engine.on('anomaly', (item) => hits.push(item.detector));
  engine.feed(ra('fe80::1'));
  engine.feed(ra('fe80::2'));
  engine.feed(ra('fe80::2'));
  assert.deepStrictEqual(hits, ['rogue-ra']);
});
