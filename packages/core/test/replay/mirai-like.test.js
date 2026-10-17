'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('a telnet scan plus a GRE flood is a multi-stage incident', () => {
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any} */
  let incident = null;
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.on('incident', (item) => {
    incident = item;
  });
  for (let i = 1; i <= 12; i++) {
    engine.feed({
      type: 'flow',
      device: 'cam',
      ts: 5000,
      srcIp: '10.0.0.8',
      srcPort: 50000 + i,
      dstIp: `1.2.3.${i}`,
      dstPort: 23,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 15,
    });
  }
  engine.feed({
    type: 'flow',
    device: 'cam',
    ts: 6000,
    srcIp: '10.0.0.8',
    srcPort: 0,
    dstIp: '198.51.100.10',
    dstPort: 0,
    proto: 'gre',
    direction: 'out',
    bytesOut: 8000,
    bytesIn: 0,
    pktsOut: 800,
    pktsIn: 0,
    durationMs: 1000,
  });
  const ids = new Set(anomalies.map((item) => item.detector));
  assert.ok(ids.has('horizontal-scan'));
  assert.ok(ids.has('packet-flood'));
  assert.ok(incident);
  assert.ok(incident.stages.includes('spread'));
  assert.ok(incident.stages.includes('impact'));
});
