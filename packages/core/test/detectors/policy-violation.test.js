'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

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
    dstPort: 80,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 10,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 10,
    dstName: 'www.a.example',
    ...extra,
  };
}

test('policy rules match direction, proto, port, hour, and destination', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T0'],
    policy: [
      { id: 'in-only', match: { direction: 'in' } },
      { id: 'udp-only', match: { proto: 'udp' } },
      { id: 'ports', match: { port: [22, 23] } },
      { id: 'night', match: { hour: [3] } },
      { id: 'wild', match: { dst: '*.example' } },
      { id: 'exact', match: { dst: 'www.a.example' } },
      { id: 'family', match: { dst: 'a.example' } },
      { id: 'miss', match: { dst: 'other.test' } },
    ],
  });
  /** @type {string[]} */
  const hits = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'policy-violation') hits.push(item.data.rule);
  });
  engine.feed(flow());
  engine.feed(flow());
  assert.deepStrictEqual(hits, ['wild', 'exact', 'family']);
  const saved = engine.exportBaseline({ createdAt: 1 });
  const bad = JSON.parse(JSON.stringify(saved));
  bad.devices.d.detectors['policy-violation'].state.fired = [1];
  assert.throws(
    () => createEngine({ learnMs: 0, tiers: ['T0'] }).importBaseline(bad),
    /fired must be strings/,
  );
  const huge = JSON.parse(JSON.stringify(saved));
  huge.devices.d.detectors['policy-violation'].state.fired = Array.from(
    { length: 5001 },
    (_, i) => `k${i}`,
  );
  assert.throws(
    () => createEngine({ learnMs: 0, tiers: ['T0'] }).importBaseline(huge),
    /exceeds cap/,
  );
});
