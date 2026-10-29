'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine, HubvikError } = require('../src/index.js');

/**
 * A hard rule so the check runs while the device is still learning.
 * @param {import('../src/index.js').Engine} engine
 */
function demo(engine) {
  engine.use({
    id: 'report-demo',
    version: 1,
    requires: ['T0'],
    hardRule: true,
    defaults: { severity: 'low' },
    createState() {
      return {};
    },
    /**
     * @param {unknown} _state
     * @param {any} ev
     */
    check(_state, ev) {
      return {
        severity: 'low',
        confidence: 0.8,
        ts: ev.ts,
        actual: `talked to ${ev.dst}`,
        expected: 'a known host',
        data: { dst: ev.dst },
      };
    },
  });
}

test('digest and exportDecisions read live anomalies and open no socket', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3, explainCap: 10 });
  demo(engine);
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  engine.feed({ device: 'cam', dst: 'b.example', bytes: 10, ts: 2_000 });
  const early = engine.digest(1_500);
  assert.strictEqual(early.sinceTs, 1_500);
  assert.strictEqual(early.devices.length, 1);
  assert.strictEqual(early.devices[0].device, 'cam');
  assert.strictEqual(early.devices[0].count, 1);
  assert.match(early.devices[0].text, /report-demo: talked to b\.example/);
  assert.match(early.devices[0].text, /Expected a known host/);
  const all = engine.digest(0);
  assert.strictEqual(all.devices[0].count, 2);
  const decisions = JSON.parse(engine.exportDecisions());
  assert.strictEqual(decisions.decisions.length, 2);
  assert.strictEqual(decisions.decisions[0].destination, 'a.example');
  assert.strictEqual(decisions.decisions[1].detector, 'report-demo');
  assert.strictEqual(decisions.decisions[1].confidence, 0.8);
  assert.throws(
    () => engine.digest(Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'DIGEST_SINCE_IS_INVALID',
  );
});

test('the report ring stops at explainCap', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3, explainCap: 1 });
  demo(engine);
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  engine.feed({ device: 'cam', dst: 'b.example', bytes: 10, ts: 2_000 });
  const body = JSON.parse(engine.exportDecisions());
  assert.strictEqual(body.decisions.length, 1);
  assert.strictEqual(body.decisions[0].destination, 'b.example');
});

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '203.0.113.9',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 40,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 20,
    ...extra,
  };
}

test('inventory lists a seen device, its learned port, and does not assign a class', () => {
  const mac = 'aa:bb:cc:dd:ee:ff';
  const engine = createEngine({
    learnMs: 7 * 24 * 3600e3,
    tiers: ['T0', 'T1', 'T4', 'T5'],
  });
  engine.setDeviceClass(mac, 'camera');
  engine.feed({
    type: 'dhcp',
    device: mac,
    ts: 1_000,
    mac,
    msg: 'ack',
    serverIp: '10.0.0.1',
    requestedIp: '10.0.0.8',
  });
  engine.feed(
    flow({
      device: mac,
      ts: 2_000,
      dstPort: 443,
      dstIp: '203.0.113.9',
    }),
  );
  engine.feed(
    flow({
      device: mac,
      ts: 3_000,
      dstPort: 1883,
      dstIp: '203.0.113.10',
      dstName: 'broker.example',
    }),
  );
  const rows = engine.inventory();
  const row = rows.find((item) => item.device === mac);
  assert.ok(row);
  assert.strictEqual(row.class, 'camera');
  assert.strictEqual(row.lastSeen, 3_000);
  assert.ok(row.addresses.includes('10.0.0.8'));
  assert.ok(row.ports.includes(443));
  assert.ok(row.ports.includes(1883));
  assert.ok(row.protocols.includes('tcp'));
  assert.ok(row.apps.includes('mqtt'));
  assert.strictEqual(row.suggestions, undefined);
  const suggested = createEngine({
    learnMs: 7 * 24 * 3600e3,
    tiers: ['T0'],
    classSuggest: true,
  });
  suggested.feed({ device: 'plug', dst: 'vendor.example', bytes: 10, ts: 1_000 });
  const plug = suggested.inventory().find((item) => item.device === 'plug');
  assert.ok(plug);
  assert.ok(Array.isArray(plug.suggestions));
  assert.notStrictEqual(plug.class, 'plug');
});

test('a sharded engine merges digest rows from each shard', () => {
  const engine = createShardedEngine({
    learnMs: 7 * 24 * 3600e3,
    shards: 2,
    inline: true,
    tiers: ['T1'],
  });
  for (const device of ['one', 'two']) {
    for (let i = 0; i < 11; i += 1) {
      engine.feed(
        flow({
          device,
          ts: 1_000 + i,
          dstPort: 25,
          dstIp: '203.0.113.25',
        }),
      );
    }
  }
  const digest = engine.digest(0);
  const ids = digest.devices.map((row) => row.device).sort();
  assert.deepStrictEqual(ids, ['one', 'two']);
  for (const row of digest.devices) assert.match(row.text, /spam-relay/);
  const decisions = JSON.parse(engine.exportDecisions());
  assert.strictEqual(decisions.decisions.length, 2);
  const counts = engine.counts(0);
  assert.deepStrictEqual(counts.detectors, [{ detector: 'spam-relay', count: 2, devices: 2 }]);
  assert.deepStrictEqual(engine.hints(0).hints, []);
  const quiet = engine.quiet(10_000, 1_000);
  assert.deepStrictEqual(quiet.devices.map((row) => row.device).sort(), ['one', 'two']);
});

test('counts, hints, noisy, and quiet read state and do not emit', () => {
  const engine = createEngine({ learnMs: 0, responseHints: true, tiers: ['T0'] });
  engine.lock();
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (row) => anomalies.push(row));
  engine.feed({ device: 'aa:bb:cc:dd:ee:ff', dst: 'new.example', bytes: 20, ts: 1_000 });
  const hit = anomalies.find((row) => row.detector === 'new-destination');
  assert.ok(hit);
  assert.ok(engine.counts(0).detectors.some((row) => row.detector === 'new-destination'));
  const hints = engine.hints(0);
  assert.ok(hints.hints.some((row) => row.action === 'review' && row.reversible === true));
  assert.throws(
    () => engine.hints(Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'HINTS_SINCE_IS_INVALID',
  );
  const before = anomalies.length;
  const quiet = engine.quiet(5_000, 1_000);
  assert.strictEqual(anomalies.length, before);
  assert.strictEqual(quiet.devices[0].device, 'aa:bb:cc:dd:ee:ff');
  assert.strictEqual(engine.quiet(1_500, 1_000).devices.length, 0);
  assert.throws(
    () => engine.quiet(1, -1),
    (err) => err instanceof HubvikError && err.code === 'QUIET_MS_IS_INVALID',
  );
  for (let i = 0; i < 10; i += 1) engine.feedback(hit.id, 'fp');
  assert.strictEqual(engine.noisy()[0].detector, 'new-destination');
  assert.strictEqual(engine.noisy()[0].n, 10);

  const off = createEngine({ learnMs: 7 * 24 * 3600e3 });
  demo(off);
  off.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1 });
  assert.deepStrictEqual(off.hints(0).hints, []);
  assert.throws(
    () => off.counts('0'),
    (err) => err instanceof HubvikError && err.code === 'COUNTS_SINCE_IS_INVALID',
  );
});
