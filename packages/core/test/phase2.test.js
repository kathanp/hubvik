'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const TIERS = ['T0', 'T1', 'T2'];

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 200,
    bytesIn: 200,
    pktsOut: 2,
    pktsIn: 2,
    durationMs: 20,
    ...extra,
  };
}

/**
 * @param {import('../src/index.js').Engine} engine
 * @param {string} id
 */
function take(engine, id) {
  /** @type {any[]} */
  const out = [];
  engine.on('anomaly', (item) => {
    if (item.detector === id) out.push(item);
  });
  return out;
}

test('new-domain-family ignores a new hostname on a known registrable domain', () => {
  const engine = createEngine({ learnMs: 1000, tiers: TIERS });
  const alerts = take(engine, 'new-domain-family');
  engine.feed({ device: 'd', dst: 'a.vendor.com', bytes: 10, ts: 0 });
  engine.lock('d');
  engine.feed({ device: 'd', dst: 'b.vendor.com', bytes: 10, ts: 120_000 });
  engine.feed({ device: 'd', dst: 'cdn.other.example', bytes: 10, ts: 180_000 });
  assert.deepStrictEqual(
    alerts.map((item) => item.actual),
    ['other.example'],
  );
});

test('new-port, new-protocol, bogon, and lateral movement', () => {
  const engine = createEngine({ learnMs: 1000, tiers: TIERS });
  const ports = take(engine, 'new-port');
  const protos = take(engine, 'new-protocol');
  const bogons = take(engine, 'bogon-destination');
  const lateral = take(engine, 'lan-lateral');
  engine.feed(flow({ ts: 0 }));
  engine.lock('d');
  engine.feed(flow({ ts: 120_000, dstPort: 23 }));
  engine.feed(flow({ ts: 180_000, proto: 'gre' }));
  engine.feed(flow({ ts: 240_000, dstIp: '203.0.113.9' }));
  engine.feed(flow({ ts: 300_000, direction: 'lan', dstIp: '10.0.0.50', srcIp: '10.0.0.8' }));
  assert.strictEqual(ports.length, 2);
  assert.strictEqual(protos.length, 1);
  assert.strictEqual(bogons.length, 1);
  assert.strictEqual(lateral.length, 1);
});

test('inbound telnet and ADB fire during learning', () => {
  const engine = createEngine({ learnMs: 10 * 24 * 3600e3, tiers: TIERS });
  const inbound = take(engine, 'inbound-from-wan');
  const adb = take(engine, 'adb-exposure');
  engine.feed(
    flow({
      ts: 0,
      direction: 'in',
      srcIp: '1.2.3.50',
      dstPort: 23,
      dstIp: '10.0.0.8',
    }),
  );
  engine.feed(
    flow({
      ts: 1000,
      direction: 'lan',
      srcIp: '10.0.0.9',
      dstIp: '10.0.0.8',
      dstPort: 5555,
    }),
  );
  assert.strictEqual(inbound.length, 1);
  assert.strictEqual(inbound[0].hardRule, true);
  assert.strictEqual(adb.length, 1);
});

test('horizontal scan of telnet ports fires during learning', () => {
  const engine = createEngine({ learnMs: 10 * 24 * 3600e3, tiers: TIERS, windowMs: 60_000 });
  const alerts = take(engine, 'horizontal-scan');
  for (let i = 1; i <= 12; i++) {
    engine.feed(flow({ ts: 1000 + i, dstIp: `1.2.3.${i}`, dstPort: 23 }));
  }
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'critical');
});

test('threat indicators match domain, cidr, and ignore expired entries', () => {
  const engine = createEngine({ learnMs: 10 * 24 * 3600e3 });
  const alerts = take(engine, 'threat-intel-match');
  engine.loadIndicators([
    { value: 'evil.example', type: 'domain', source: 'lab', confidence: 0.7 },
    { value: '203.0.113.0/24', type: 'cidr', source: 'lab' },
    { value: 'old.example', type: 'domain', source: 'lab', expiresTs: 50 },
  ]);
  engine.feed({ device: 'd', dst: 'a.evil.example', bytes: 1, ts: 100 });
  engine.feed({ device: 'd', dst: '203.0.113.8', bytes: 1, ts: 200 });
  engine.feed({ device: 'd', dst: 'old.example', bytes: 1, ts: 80 });
  assert.deepStrictEqual(
    alerts.map((item) => item.actual),
    ['evil.example', '203.0.113.0/24'],
  );
});

test('packet flood, reflection, and coap amplification', () => {
  const engine = createEngine({ learnMs: 10 * 24 * 3600e3, tiers: TIERS });
  const flood = take(engine, 'packet-flood');
  const reflect = take(engine, 'reflection-participation');
  const coap = take(engine, 'coap-amplification');
  engine.feed(flow({ ts: 0, pktsOut: 800, pktsIn: 0, bytesOut: 8000, bytesIn: 0 }));
  engine.feed(
    flow({
      ts: 1000,
      proto: 'udp',
      direction: 'out',
      srcPort: 1900,
      dstPort: 80,
      dstIp: '1.2.3.9',
      bytesOut: 2000,
      bytesIn: 100,
    }),
  );
  engine.feed(
    flow({
      ts: 2000,
      proto: 'udp',
      direction: 'out',
      srcPort: 5683,
      dstPort: 9999,
      dstIp: '1.2.3.10',
      bytesOut: 2000,
      bytesIn: 0,
    }),
  );
  assert.strictEqual(flood.length, 1);
  assert.strictEqual(reflect.length, 2);
  assert.strictEqual(coap.length, 1);
});

test('dns rebinding and a private answer for a public name', () => {
  const engine = createEngine({ learnMs: 0, tiers: TIERS });
  const rebind = take(engine, 'dns-rebinding');
  const priv = take(engine, 'private-answer-for-public-name');
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 0,
    qname: 'evil.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '10.1.1.1', ttl: 0 }],
  });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1000,
    qname: 'kim.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '0.0.0.0', ttl: 0 }],
  });
  assert.strictEqual(rebind.length, 2);
  assert.strictEqual(priv.length, 2);
});

test('policy, tftp, smtp relay, and a device that appears after learning', () => {
  const engine = createEngine({
    learnMs: 1000,
    tiers: TIERS,
    policy: [{ id: 'no-telnet', severity: 'high', match: { direction: 'out', port: 23 } }],
  });
  const policy = take(engine, 'policy-violation');
  const tftp = take(engine, 'tftp-activity');
  const spam = take(engine, 'spam-relay');
  const appeared = take(engine, 'new-device');
  engine.feed(flow({ ts: 0, dstPort: 23 }));
  engine.feed(flow({ ts: 500, proto: 'udp', dstPort: 69, direction: 'out' }));
  for (let i = 0; i < 11; i++) engine.feed(flow({ ts: 600 + i, dstPort: 25 }));
  engine.feed({ device: 'other', dst: 'a.example', bytes: 1, ts: 5000 });
  assert.strictEqual(policy.length, 1);
  assert.strictEqual(tftp.length, 1);
  assert.strictEqual(spam.length, 1);
  assert.deepStrictEqual(
    appeared.map((item) => item.device),
    ['other'],
  );
});

test('learning warnings cover gre, telnet, and an NXDOMAIN burst', () => {
  const engine = createEngine({ learnMs: 10 * 24 * 3600e3, tiers: TIERS });
  /** @type {string[]} */
  const warnings = [];
  engine.on('warning', (warning) => {
    if (warning.code === 'SUSPICIOUS_LEARNING') warnings.push(warning.message);
  });
  engine.feed(flow({ ts: 0, proto: 'gre' }));
  engine.feed(flow({ ts: 1000, dstPort: 23 }));
  for (let i = 0; i < 10; i++) {
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 2000 + i,
      qname: `n${i}.example`,
      qtype: 'A',
      rcode: 'NXDOMAIN',
      resolver: '10.0.0.1',
    });
  }
  assert.strictEqual(warnings.length, 3);
});
