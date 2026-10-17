'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {number} pkts
 * @param {number} bytesOut
 * @param {number} [bytesIn]
 */
function flow(ts, pkts, bytesOut, bytesIn = 0) {
  return {
    type: 'flow',
    device: 'cam',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'udp',
    direction: 'out',
    bytesOut,
    bytesIn,
    pktsOut: pkts,
    pktsIn: 0,
    durationMs: 40,
  };
}

test('egress-flood also fires at ten times the learned packet maximum', () => {
  const engine = createEngine({ learnMs: 120_000, tiers: ['T1'], windowMs: 60_000 });
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'egress-flood') alerts.push(item);
  });
  engine.feed(flow(1_000, 600, 600, 600));
  engine.feed(flow(61_000, 1, 1, 1));
  engine.lock('cam');
  engine.feed(flow(62_000, 5_999, 6_000, 0));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].hardRule, false);
  assert.strictEqual(alerts[0].data.packets, 6_000);
});
