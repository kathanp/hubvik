'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, HubvikError } = require('../src/index.js');
const { attachMeta } = require('../src/engine/baseline.js');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

test('coverage names a missing tier and does not detect', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (row) => anomalies.push(row));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  const snap = () => JSON.stringify(engine.exportBaseline({ createdAt: 1 }));
  const before = snap();
  const seen = anomalies.length;
  const report = engine.coverage(1000);
  assert.strictEqual(report.tiers.T0.enabled, true);
  assert.strictEqual(report.tiers.T0.eventsSeen, 1);
  assert.strictEqual(report.tiers.T2.enabled, false);
  assert.strictEqual(report.tiers.T2.eventsSeen, 0);
  const tunnel = report.techniques['T1071.004'];
  assert.ok(tunnel);
  assert.strictEqual(tunnel.coveredLive, false);
  assert.match(String(tunnel.blockedBy), /T2/);
  assert.strictEqual(snap(), before);
  assert.strictEqual(anomalies.length, seen);
});

test('selftest is missing tiers on T0 and fires on every tier', () => {
  const narrow = createEngine({ learnMs: 0, tiers: ['T0'] });
  /** @type {any[]} */
  const live = [];
  narrow.on('anomaly', (row) => live.push(row));
  narrow.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  const before = JSON.stringify(narrow.exportBaseline({ createdAt: 1 }));
  const seen = live.length;
  const missing = narrow.selftest();
  assert.strictEqual(JSON.stringify(narrow.exportBaseline({ createdAt: 1 })), before);
  assert.strictEqual(live.length, seen);
  for (const row of missing) {
    if (row.scenario === 'horizontal scan' || row.scenario === 'DNS tunnel') {
      assert.ok(row.missing.length > 0);
      assert.match(String(row.missingReason), /T[12]/);
    }
  }
  const wide = createEngine({ learnMs: 0, tiers: TIERS });
  const fired = wide.selftest();
  for (const row of fired) {
    assert.deepStrictEqual(row.missing, [], `${row.scenario} missed ${row.missing.join(',')}`);
  }
});

test('a long learn window still fires the canned attacks after learning', () => {
  const engine = createEngine({ learnMs: 7 * DAY, tiers: TIERS });
  const rows = engine.selftest();
  for (const row of rows) {
    assert.deepStrictEqual(row.missing, [], row.scenario);
  }
});

test('benign devices suggest lock after the learning window', () => {
  for (const profile of CLASS_NAMES) {
    const events = simulate({ profile, days: 8, seed: 7, startTs: T0 });
    const engine = createEngine({ learnMs: 7 * DAY });
    /** @type {string[]} */
    const codes = [];
    engine.on('warning', (warning) => {
      if (warning.code === 'LOCK_SUGGESTED') codes.push(warning.device);
    });
    for (const event of events) engine.feed(event);
    engine.flush(T0 + 8 * DAY);
    const device = events[0].device;
    const readiness = engine.stats().learningQuality[device].readiness;
    assert.strictEqual(readiness.suggestLock, true, `${profile} ${readiness.reasons.join(',')}`);
    assert.strictEqual(readiness.score, 100);
    assert.ok(codes.includes(device));
  }
});

test('an attack during learning keeps suggestLock false', () => {
  const engine = createEngine({ learnMs: 7 * DAY, tiers: ['T0', 'T1'] });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  for (let i = 1; i <= 21; i += 1) {
    engine.feed({
      type: 'flow',
      device: 'd',
      ts: 2000 + i,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: `192.0.2.${i}`,
      dstPort: 23,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
    });
  }
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 7 * DAY + 5000 });
  const readiness = engine.stats().learningQuality.d.readiness;
  assert.strictEqual(readiness.suggestLock, false);
  assert.ok(readiness.reasons.some((reason) => reason.includes('horizontal-scan')));
});

test('a signed model pack seeds only an empty classed device', () => {
  const engine = createEngine({ modelPack: true, shadow: true, learnMs: 7 * DAY, tiers: ['T0'] });
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed({ device: 'peer', dst: 'cdn.example', bytes: 10, ts: 1000 });
  engine.setDeviceClass('cam', 'camera');
  engine.feed({ device: 'busy', dst: 'busy.example', bytes: 10, ts: 1000 });
  engine.setDeviceClass('busy', 'camera');
  const beforeBusy = JSON.stringify(engine.exportBaseline({ devices: ['busy'], createdAt: 1 }));
  const pack = attachMeta(
    {
      version: 3,
      model: 'camera',
      engine: { windowMs: 60000, pkg: 'hubvik@3.5.0' },
      devices: {
        camera: {
          detectors: {
            'new-destination': { v: 1, state: { dsts: ['evil.example'], alerted: [] } },
          },
        },
      },
    },
    { createdAt: 0, windowMs: 60000, pkg: 'hubvik@3.5.0', sign: 'pack-key' },
  );
  const off = createEngine({ learnMs: 0 });
  assert.throws(
    () => off.loadModelPack(pack, { verify: 'pack-key' }),
    (error) => error instanceof HubvikError && error.code === 'MODEL_PACK_IS_OFF',
  );
  assert.throws(
    () =>
      engine.loadModelPack(
        { ...pack, sig: { alg: 'HMAC-SHA256', mac: '00' } },
        { verify: 'pack-key' },
      ),
    (error) => error instanceof HubvikError && error.code === 'BASELINE_SIGNATURE_MISMATCH',
  );
  engine.loadModelPack(pack, { verify: 'pack-key' });
  const cam = engine.exportBaseline({ devices: ['cam'] });
  assert.deepStrictEqual(cam.devices.cam.detectors['new-destination'].state.dsts, ['evil.example']);
  assert.strictEqual(
    JSON.stringify(engine.exportBaseline({ devices: ['busy'], createdAt: 1 })),
    beforeBusy,
  );
  assert.strictEqual(engine.stats().learningQuality.cam, undefined);
  assert.ok(found.some((row) => row.detector === 'fleet-baseline-poisoning'));
  const again = attachMeta(
    {
      version: 3,
      model: 'camera',
      engine: { windowMs: 60000, pkg: 'hubvik@3.5.0' },
      devices: {
        camera: {
          detectors: {
            'new-destination': { v: 1, state: { dsts: ['other.example'], alerted: [] } },
          },
        },
      },
    },
    { createdAt: 0, windowMs: 60000, pkg: 'hubvik@3.5.0', sign: 'pack-key' },
  );
  engine.loadModelPack(again, { verify: 'pack-key' });
  const kept = engine.exportBaseline({ devices: ['cam'] });
  assert.deepStrictEqual(kept.devices.cam.detectors['new-destination'].state.dsts, [
    'evil.example',
  ]);
  engine.setDeviceClass('later', 'camera');
  const later = engine.exportBaseline({ devices: ['later'], createdAt: 1 });
  assert.deepStrictEqual(later.devices.later.detectors['new-destination'].state.dsts, [
    'other.example',
  ]);
  assert.throws(
    () => engine.loadModelPack(null, { verify: 'pack-key' }),
    (error) => error instanceof HubvikError && error.code === 'MODEL_PACK_IS_INVALID',
  );
  assert.throws(
    () => engine.selftest({ scenarios: ['missing'] }),
    (error) => error instanceof HubvikError && error.code === 'SELFTEST_IS_INVALID',
  );
});
