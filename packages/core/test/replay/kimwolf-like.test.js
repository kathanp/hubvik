'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('proxy session, LAN ADB sweep, and an RPC lookup become one incident', () => {
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T1', 'T2'] });
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any} */
  let incident = null;
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.on('incident', (item) => {
    incident = item;
  });
  const names = [
    'www.amazon.com',
    'www.walmart.com',
    'www.facebook.com',
    'www.reddit.com',
    'www.ticketmaster.com',
    'www.stubhub.com',
  ];
  names.forEach((dstName, index) => {
    engine.feed({
      type: 'flow',
      device: 'box',
      ts: 1000 + index,
      srcIp: '10.0.0.20',
      srcPort: 42000,
      dstIp: `9.9.0.${index + 1}`,
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 500,
      bytesIn: 2000,
      pktsOut: 4,
      pktsIn: 6,
      durationMs: 100,
      dstName,
    });
  });
  for (let i = 1; i <= 12; i++) {
    engine.feed({
      type: 'flow',
      device: 'box',
      ts: 2000,
      srcIp: '10.0.0.20',
      srcPort: 43000 + i,
      dstIp: `10.0.0.${i}`,
      dstPort: 5555,
      proto: 'tcp',
      direction: 'lan',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 20,
    });
  }
  engine.feed({
    type: 'dns',
    device: 'box',
    ts: 3000,
    qname: 'mainnet.infura.io',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  const ids = new Set(anomalies.map((item) => item.detector));
  assert.ok(ids.has('proxy-relay'));
  assert.ok(ids.has('horizontal-scan'));
  assert.ok(ids.has('adb-exposure'));
  assert.ok(ids.has('blockchain-c2'));
  assert.ok(incident);
  assert.ok(incident.stages.length >= 3);
  assert.ok(incident.summary.includes('box'));
});
