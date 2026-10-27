'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('horizontal-scan keeps at most 512 learned ports', () => {
  const engine = createEngine({ learnMs: 120_000, tiers: ['T1'], windowMs: 60_000 });
  for (let port = 1; port <= 600; port += 1) {
    engine.feed({
      type: 'flow',
      device: 'cam',
      ts: 1_000,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: `1.2.3.${(port % 200) + 1}`,
      dstPort: port,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
      tcpOutcome: 'no-response',
    });
  }
  engine.feed({
    type: 'flow',
    device: 'cam',
    ts: 61_000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.9',
    dstPort: 80,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 40,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 10,
    tcpOutcome: 'no-response',
  });
  const saved = engine.exportBaseline({ createdAt: 1 });
  const max = saved.devices.cam.detectors['horizontal-scan'].state.max;
  assert.ok(max.length <= 512);
  assert.doesNotThrow(() => engine.importBaseline(saved));
});
