'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('a known SNI that changes certificate issuer is a MITM', () => {
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T3'] });
  engine.feed({
    type: 'tls',
    device: 'cam',
    ts: 1000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 'video.vendor.com',
    cert: { issuer: 'Vendor CA' },
  });
  engine.lock('cam');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'tls',
    device: 'cam',
    ts: 5000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 'video.vendor.com',
    cert: { issuer: 'Unexpected CA' },
  });
  const hit = anomalies.find((item) => item.detector === 'cert-change');
  assert.ok(hit);
  assert.strictEqual(hit.data.previous, 'Vendor CA');
  assert.strictEqual(hit.data.issuer, 'Unexpected CA');
});
