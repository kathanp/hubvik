'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {string} device
 * @param {number} ts
 */
function tls(device, ts) {
  return {
    type: 'tls',
    device,
    ts,
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 'www.example',
    ja4: 't13d_browser',
    version: 'TLSv1.3',
  };
}

test('smart-tv may use a browser JA4 and a camera may not', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T3'],
    browserJa4: ['t13d_browser'],
  });
  engine.setDeviceClass('tv', 'smart-tv');
  engine.setDeviceClass('cam', 'camera');
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'browser-mimic') alerts.push(item);
  });
  engine.feed(tls('tv', 0));
  engine.feed(tls('cam', 1_000));
  assert.deepStrictEqual(
    alerts.map((item) => item.device),
    ['cam'],
  );
});
