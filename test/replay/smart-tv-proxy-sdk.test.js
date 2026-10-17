'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../packages/core/src/index.js');

test('a smart TV proxy SDK followed by a LAN session is one incident', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T1', 'T2'] });
  engine.setDeviceClass('tv', 'smart-tv');
  engine.loadIndicators([
    { value: 'sdk.proxy.example', type: 'proxy-sdk', source: 'lab', confidence: 0.9 },
  ]);
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any[]} */
  const incidents = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.on('incident', (item) => incidents.push(item));
  engine.feed({
    type: 'dns',
    device: 'tv',
    ts: 1_000,
    qname: 'sdk.proxy.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '1.2.3.9', ttl: 30 }],
  });
  engine.feed({
    type: 'flow',
    device: 'tv',
    ts: 2_000,
    srcIp: '1.2.3.9',
    srcPort: 443,
    dstIp: '10.0.0.20',
    dstPort: 50000,
    proto: 'tcp',
    direction: 'in',
    bytesOut: 0,
    bytesIn: 200,
    pktsOut: 0,
    pktsIn: 2,
    durationMs: 40,
  });
  engine.feed({
    type: 'flow',
    device: 'tv',
    ts: 2_400,
    srcIp: '10.0.0.20',
    srcPort: 50000,
    dstIp: '10.0.0.50',
    dstPort: 80,
    proto: 'tcp',
    direction: 'lan',
    bytesOut: 100,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 40,
  });
  const sdk = anomalies.filter((item) => item.detector === 'proxy-sdk-traffic');
  const lan = anomalies.filter((item) => item.detector === 'lan-via-proxy');
  assert.strictEqual(sdk.length, 1);
  assert.strictEqual(sdk[0].severity, 'medium');
  assert.strictEqual(sdk[0].data.consentPossible, true);
  assert.strictEqual(lan.length, 1);
  assert.strictEqual(lan[0].severity, 'critical');
  assert.strictEqual(incidents.at(-1).anomalyIds.length >= 2, true);
  assert.strictEqual(sdk[0].incidentId, lan[0].incidentId);
});
