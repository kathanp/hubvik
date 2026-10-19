'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../packages/core/src/index.js');
const { toFinding } = require('../../packages/export-ocsf/src/index.js');

const TV = 'aa:bb:cc:dd:ee:21';
const BOX = 'aa:bb:cc:dd:ee:22';

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    ts: 0,
    srcIp: '10.0.0.21',
    srcPort: 40000,
    dstIp: '9.9.9.9',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 40,
    ...extra,
  };
}

test('the Kimwolf LAN pivot is one campaign', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T1', 'T2'],
    identity: 'auto',
    campaigns: true,
  });
  engine.setDeviceClass(TV, 'smart-tv');
  engine.feed({ type: 'dhcp', device: TV, ts: 1, mac: TV, msg: 'ack', requestedIp: '10.0.0.21' });
  engine.feed({ type: 'dhcp', device: BOX, ts: 2, mac: BOX, msg: 'ack', requestedIp: '10.0.0.50' });
  /** @type {any[]} */
  const campaigns = [];
  engine.on('campaign', (row) => campaigns.push(row));
  engine.feed(flow({ device: TV, ts: 10_000, durationMs: 60_000, dstIp: '9.9.9.9' }));
  for (let i = 0; i < 8; i += 1) {
    engine.feed(
      flow({
        device: TV,
        ts: 70_100 + i,
        durationMs: 100,
        dstIp: `9.9.8.${i + 1}`,
        dstPort: 80,
      }),
    );
  }
  engine.feed(
    flow({
      device: TV,
      ts: 80_000,
      direction: 'in',
      srcIp: '9.9.9.9',
      dstIp: '10.0.0.21',
      bytesIn: 200,
      bytesOut: 0,
    }),
  );
  engine.feed(
    flow({
      device: TV,
      ts: 80_400,
      direction: 'lan',
      dstIp: '10.0.0.50',
      dstPort: 5555,
    }),
  );
  engine.feed(
    flow({
      device: BOX,
      ts: 81_000,
      direction: 'in',
      srcIp: '10.0.0.21',
      dstIp: '10.0.0.50',
      dstPort: 5555,
      proto: 'tcp',
    }),
  );
  engine.feed({
    type: 'dns',
    device: BOX,
    ts: 82_000,
    qname: 'eth.llamarpc.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  assert.strictEqual(campaigns.length, 1);
  assert.strictEqual(campaigns[0].devices.length, 2);
  assert.ok(campaigns[0].stages.includes('c2'));
  assert.ok(campaigns[0].stages.includes('spread'));
  assert.ok(campaigns[0].stages.includes('impact'));
  assert.strictEqual(toFinding(campaigns[0]).activity_id, 2);
});
