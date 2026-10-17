'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('a tv box relaying consumer sites from the first hour is a supply-chain suspect', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3, tiers: ['T0', 'T1', 'T2'] });
  engine.setDeviceClass('box', 'tv-box');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  const names = [
    'www.amazon.com',
    'www.ebay.com',
    'www.facebook.com',
    'www.tiktok.com',
    'www.ticketmaster.com',
    'www.eventbrite.com',
  ];
  names.forEach((dstName, index) => {
    engine.feed({
      type: 'flow',
      device: 'box',
      ts: 60_000 + index,
      srcIp: '10.0.0.20',
      srcPort: 41000,
      dstIp: `1.1.1.${index + 1}`,
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 800,
      bytesIn: 4000,
      pktsOut: 6,
      pktsIn: 8,
      durationMs: 200,
      dstName,
    });
  });
  const ids = anomalies.map((item) => item.detector);
  assert.ok(ids.includes('proxy-relay'));
  assert.ok(ids.includes('supply-chain-suspect'));
  assert.ok(
    anomalies.filter((item) => item.detector === 'proxy-relay').every((item) => item.hardRule),
  );
});
