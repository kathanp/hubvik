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

/**
 * @param {import('../../src/index.js').Engine} engine
 * @returns {string[]}
 */
function watch(engine) {
  /** @type {string[]} */
  const ids = [];
  engine.on('anomaly', (item) => {
    if (item.severity === 'low' || item.severity === 'info') return;
    ids.push(item.detector);
  });
  return ids;
}

test('a one-way UDP RTP-shaped stream to a new host fires', () => {
  const engine = createEngine({ learnMs: 1e14, tiers: ['T1'], evidence: false });
  const ids = watch(engine);
  const pkts = 900;
  const bytesOut = pkts * 1_200;
  engine.feed(flow(0, '1.2.3.4', { proto: 'udp', dstPort: 5004, bytesOut: 1_200, pktsOut: 1 }));
  engine.lock('cam');
  engine.feed(
    flow(60_000, '8.8.8.8', {
      proto: 'udp',
      dstPort: 5004,
      bytesOut,
      bytesIn: Math.round(bytesOut * 0.01),
      pktsOut: pkts,
    }),
  );
  assert.ok(ids.includes('stream-to-new-destination'));
  assert.ok(!ids.includes('egress-flood'));
});

test('a 60000-packet flood raises egress-flood and not the stream detector', () => {
  const engine = createEngine({ learnMs: 1e14, tiers: ['T1'], evidence: false });
  const ids = watch(engine);
  engine.feed(flow(0, '1.2.3.4', { proto: 'udp', dstPort: 5004, bytesOut: 1_400, pktsOut: 1 }));
  engine.lock('cam');
  engine.feed(
    flow(60_000, '8.8.8.8', {
      proto: 'udp',
      dstPort: 5004,
      bytesOut: 60_000 * 1_400,
      bytesIn: 0,
      pktsOut: 60_000,
    }),
  );
  engine.flush(120_000);
  assert.deepStrictEqual([...new Set(ids)], ['egress-flood']);
});

test('RTSP to a new host still raises stream-to-new-destination', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1'], evidence: false });
  const ids = watch(engine);
  engine.feed(flow(1_000, '1.2.3.9', { proto: 'tcp', dstPort: 554, bytesOut: 1000 }));
  assert.ok(ids.includes('stream-to-new-destination'));
});
