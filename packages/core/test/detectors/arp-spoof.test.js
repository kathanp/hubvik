'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} n
 * @param {string} mac
 */
function arp(n, mac) {
  return {
    type: 'arp',
    device: 'cam',
    ts: n,
    op: 'reply',
    ip: `10.0.${Math.floor(n / 256)}.${n % 256}`,
    mac,
  };
}

test('arp-spoof keeps at most 5000 LAN bindings', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T4'], gatewayIp: '10.0.0.1' });
  for (let i = 0; i < 5001; i += 1) {
    engine.feed(
      arp(
        i,
        `aa:bb:cc:dd:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`,
      ),
    );
  }
  const point = engine.checkpoint({ createdAt: 1 });
  const bindings = point.scratch['arp-spoof'].bindings.map;
  assert.ok(bindings.length <= 5000);
  assert.ok(
    !bindings.some(/** @param {[string, string]} pair */ (pair) => pair[0] === '10.0.19.136'),
  );
});
