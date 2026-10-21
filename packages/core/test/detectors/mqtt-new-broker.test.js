'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1_000,
    srcIp: '192.0.2.10',
    srcPort: 40000,
    dstIp: '198.51.100.10',
    dstPort: 1883,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    dstName: 'broker.vendor.example',
    ...extra,
  };
}

test('mqtt-new-broker fires once for a broker that was not learned', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T0', 'T1'] });
  engine.feed(flow({}));
  engine.lock('d');
  /** @type {any[]} */
  const found = [];
  engine.on('anomaly', (row) => {
    if (row.detector === 'mqtt-new-broker') found.push(row);
  });
  engine.feed(flow({ ts: 20_000 }));
  engine.feed(flow({ ts: 21_000, dstName: 'other.example', dstIp: '198.51.100.11' }));
  engine.feed(flow({ ts: 22_000, dstName: 'other.example', dstIp: '198.51.100.11' }));
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].actual, 'other.example');
  assert.strictEqual(found[0].data.port, 1883);
});
