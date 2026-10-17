'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {string} dstIp
 * @param {{ proto?: string, dstPort?: number, bytesOut?: number, bytesIn?: number, pktsOut?: number }} [extra]
 */
function flow(ts, dstIp, extra = {}) {
  return {
    type: 'flow',
    device: 'cam',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp,
    dstPort: extra.dstPort == null ? 80 : extra.dstPort,
    proto: extra.proto || 'tcp',
    direction: 'out',
    bytesOut: extra.bytesOut == null ? 60 : extra.bytesOut,
    bytesIn: extra.bytesIn || 0,
    pktsOut: extra.pktsOut == null ? 1 : extra.pktsOut,
    pktsIn: 0,
    durationMs: 10,
  };
}

test('a one-way UDP flood does not raise stream-to-new-destination', () => {
  const engine = createEngine({ learnMs: 1e14, tiers: ['T1'], evidence: false });
  /** @type {string[]} */
  const ids = [];
  engine.on('anomaly', (item) => {
    if (item.severity === 'low' || item.severity === 'info') return;
    ids.push(item.detector);
  });
  engine.feed(flow(0, '45.2.1.10', { proto: 'udp', dstPort: 80 }));
  engine.lock('cam');
  engine.feed(
    flow(60_000, '45.2.1.11', {
      proto: 'udp',
      dstPort: 80,
      bytesOut: 20_000_000,
      bytesIn: 0,
      pktsOut: 5_000,
    }),
  );
  engine.flush(120_000);
  assert.ok(ids.includes('egress-flood'));
  assert.ok(!ids.includes('stream-to-new-destination'));
});

test('RTSP to a new host still raises stream-to-new-destination', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1'], evidence: false });
  /** @type {string[]} */
  const ids = [];
  engine.on('anomaly', (item) => ids.push(item.detector));
  engine.feed(flow(1_000, '203.0.113.10', { proto: 'tcp', dstPort: 554, bytesOut: 1000 }));
  assert.ok(ids.includes('stream-to-new-destination'));
});

test('a two-way UDP upload to a new host still raises stream-to-new-destination', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1'], evidence: false });
  /** @type {string[]} */
  const ids = [];
  engine.on('anomaly', (item) => ids.push(item.detector));
  engine.feed(
    flow(1_000, '203.0.113.11', {
      proto: 'udp',
      dstPort: 443,
      bytesOut: 2_000_000,
      bytesIn: 200_000,
      pktsOut: 10,
    }),
  );
  assert.ok(ids.includes('stream-to-new-destination'));
});
