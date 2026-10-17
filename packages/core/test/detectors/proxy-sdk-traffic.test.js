'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('proxy-sdk-traffic is high off a television class', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T2'] });
  engine.setDeviceClass('cam', 'camera');
  engine.loadIndicators([
    { value: 'sdk.proxy.example', type: 'proxy-sdk', source: 'lab', confidence: 0.9 },
  ]);
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'proxy-sdk-traffic') alerts.push(item);
  });
  engine.feed({
    type: 'tls',
    device: 'cam',
    ts: 0,
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 'cdn.sdk.proxy.example',
  });
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'high');
  assert.strictEqual(alerts[0].data.consentPossible, false);
  assert.strictEqual(alerts[0].hardRule, false);
});
