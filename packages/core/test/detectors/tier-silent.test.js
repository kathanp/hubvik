'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

const HOUR = 3600e3;

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 0,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    dstName: 'video.vendor.com',
    ...extra,
  };
}

test('a quiet DNS tier names the DNS detectors', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T2'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 0,
    qname: 'video.vendor.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  for (let hour = 0; hour <= 6; hour++) {
    engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 10, ts: hour * HOUR });
    engine.feed(flow({ ts: hour * HOUR }));
  }
  engine.tick(6 * HOUR);
  const hit = anomalies.find((item) => item.detector === 'tier-silent');
  assert.ok(hit);
  assert.strictEqual(hit.data.tier, 'T2');
  assert.ok(hit.data.detectors.includes('nxdomain-burst'));
  assert.ok(hit.data.detectors.includes('dns-rebinding'));
});
