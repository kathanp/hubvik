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

test('a tier that has never been seen stays quiet', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 10, ts: 0 });
  engine.tick(7 * HOUR);
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'tier-silent'),
    [],
  );
});

test('T4 stays quiet for a day and alerts after 26 hours', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T4'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 0,
    mac: 'aa:bb:cc:dd:ee:ff',
    msg: 'ack',
    serverIp: '10.0.0.1',
  });
  engine.feed(flow({ ts: 7 * HOUR }));
  engine.tick(7 * HOUR);
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'tier-silent'),
    [],
  );
  engine.feed(flow({ ts: 26 * HOUR }));
  engine.tick(26 * HOUR);
  const hit = anomalies.find((item) => item.detector === 'tier-silent');
  assert.ok(hit);
  assert.strictEqual(hit.data.tier, 'T4');
});
