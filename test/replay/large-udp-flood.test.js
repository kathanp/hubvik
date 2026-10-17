'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../packages/core/src/index.js');

test('a large UDP upload to one public address is an egress flood during learning', () => {
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T1'] });
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'egress-flood') alerts.push(item);
  });
  engine.feed({
    type: 'flow',
    device: 'cam',
    ts: 1_000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'udp',
    direction: 'out',
    bytesOut: 60_000 * 1_400,
    bytesIn: 0,
    pktsOut: 60_000,
    pktsIn: 0,
    durationMs: 1_000,
  });
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'critical');
  assert.strictEqual(alerts[0].hardRule, true);
  assert.strictEqual(alerts[0].dedupGroup, 'flood');
  assert.strictEqual(alerts[0].data.bytesPerPacket, 1_400);
});
