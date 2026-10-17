'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

const HOUR = 3600e3;

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
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    dstName: 'video.vendor.com',
    ...extra,
  };
}

test('a quiet DNS tier names the DNS detectors', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T2'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 0,
    qname: 'video.vendor.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  for (let hour = 0; hour <= 6; hour++) {
    engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 10, ts: hour * HOUR });
    engine.feed(flow({ ts: hour * HOUR }));
  }
  engine.tick(6 * HOUR);
  const hit = anomalies.find((item) => item.detector === 'tier-silent');
  assert.ok(hit);
  assert.strictEqual(hit.data.tier, 'T2');
  assert.ok(hit.data.detectors.includes('nxdomain-burst'));
  assert.ok(hit.data.detectors.includes('dns-rebinding'));
});

test('a tier that has never been seen stays quiet', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 10, ts: 0 });
  engine.tick(7 * HOUR);
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'tier-silent'),
    [],
  );
});

test('T4 stays quiet for a day and alerts after 26 hours', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T4'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 0,
    mac: 'aa:bb:cc:dd:ee:ff',
    msg: 'ack',
    serverIp: '10.0.0.1',
  });
  engine.feed(flow({ ts: 7 * HOUR }));
  engine.tick(7 * HOUR);
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'tier-silent'),
    [],
  );
  engine.feed(flow({ ts: 26 * HOUR }));
  engine.tick(26 * HOUR);
  const hit = anomalies.find((item) => item.detector === 'tier-silent');
  assert.ok(hit);
  assert.strictEqual(hit.data.tier, 'T4');
});

test('a tick before any event does not warn about unseen tiers', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1'] });
  /** @type {string[]} */
  const codes = [];
  engine.on('warning', (warning) => codes.push(warning.code));
  engine.tick(1_000);
  assert.deepStrictEqual(codes, []);
});

test('a tier with no events warns once after learning and does not alert', () => {
  const engine = createEngine({ learnMs: 60_000, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const warnings = [];
  /** @type {any[]} */
  const anomalies = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.tick(59_000);
  assert.deepStrictEqual(
    warnings.filter((warning) => warning.code === 'TIER_NEVER_SEEN'),
    [],
  );
  engine.tick(60_000);
  engine.tick(120_000);
  const never = warnings.filter((warning) => warning.code === 'TIER_NEVER_SEEN');
  assert.strictEqual(never.length, 1);
  assert.strictEqual(never[0].message, 'T1 had no events by the end of learning');
  assert.strictEqual(never[0].ts, 60_000);
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'tier-silent'),
    [],
  );

  const seen = createEngine({ learnMs: 60_000, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const seenWarnings = [];
  seen.on('warning', (warning) => seenWarnings.push(warning));
  seen.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  seen.feed(flow({ ts: 1_000 }));
  seen.tick(60_000);
  assert.deepStrictEqual(
    seenWarnings.filter((warning) => warning.code === 'TIER_NEVER_SEEN'),
    [],
  );
});
