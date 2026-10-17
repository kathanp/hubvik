'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { PROFILES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {string} mac
 * @param {string} fingerprint
 * @param {number} ts
 */
function dhcp(mac, fingerprint, ts) {
  return {
    type: 'dhcp',
    device: 'd',
    ts,
    mac,
    msg: 'ack',
    fingerprint,
  };
}

test('identity-change fires when a learned MAC presents a new fingerprint', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'identity-change') alerts.push(item);
  });
  /** @type {string[]} */
  const reasons = [];
  engine.on('warning', (warning) => {
    if (warning.code === 'SUSPICIOUS_LEARNING') reasons.push(warning.reason);
  });
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 0));
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6,12', 1_000));
  assert.strictEqual(alerts.length, 0);
  assert.deepStrictEqual(reasons, ['identity-change']);
  engine.lock('d');
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 20_000));
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6,12', 21_000));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'high');
  assert.strictEqual(alerts[0].data.previous, '1,3,6');
  assert.strictEqual(alerts[0].data.fingerprint, '1,3,6,12');
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6,12', 22_000));
  assert.strictEqual(alerts.length, 1);
});

test('an allowed fingerprint does not alert after lock', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'identity-change') alerts.push(item);
  });
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 0));
  engine.allow('d', 'fingerprint', '1,3,6,12');
  engine.lock('d');
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6,12', 20_000));
  assert.strictEqual(alerts.length, 0);
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '9,9,9', 21_000));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].data.fingerprint, '9,9,9');
});

test('identity-change stays quiet on 14 benign days for every class', () => {
  for (const profile of Object.keys(PROFILES)) {
    const engine = createEngine({ learnMs: 7 * DAY, tiers: TIERS });
    /** @type {any[]} */
    const alerts = [];
    engine.on('anomaly', (item) => {
      if (item.detector === 'identity-change') alerts.push(item);
    });
    for (const event of simulate({ profile, days: 14, seed: 1, startTs: T0, rich: true })) {
      engine.feed(event);
    }
    assert.deepStrictEqual(alerts, [], profile);
  }
});

test('identity-change keeps at most 5000 MACs', () => {
  const engine = createEngine({ learnMs: 10_000_000, tiers: ['T4'] });
  for (let i = 0; i < 5001; i++) engine.feed(dhcp(`mac-${i}`, '1,3,6', i));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const macs = saved.devices.d.detectors['identity-change'].state.macs;
  assert.strictEqual(macs.length, 5000);
  assert.strictEqual(
    macs.some((pair) => pair[0] === 'mac-5000'),
    false,
  );
  engine.lock('d');
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'identity-change') alerts.push(item);
  });
  engine.feed(dhcp('mac-5000', '9,9,9', 6_000_000));
  engine.feed(dhcp('mac-0', '9,9,9', 6_000_001));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].data.mac, 'mac-0');
  const blown = JSON.parse(JSON.stringify(saved));
  blown.devices.d.detectors['identity-change'].state.macs.push(['mac-extra', '1,3,6']);
  const next = createEngine({ learnMs: 10_000_000, tiers: ['T4'] });
  assert.throws(() => next.importBaseline(blown), /exceeds cap/);
});

test('an allowed fingerprint is stored and a bad allow list is rejected', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 0));
  engine.feed({ ...dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 1), device: 'e' });
  engine.allow('d', 'fingerprint', '9,9,9');
  engine.allow('d', 'fingerprint', '1,3,6,12');
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.deepStrictEqual(saved.devices.d.detectors['identity-change'].state.allowed, [
    '1,3,6,12',
    '9,9,9',
  ]);
  const bad = JSON.parse(JSON.stringify(saved));
  bad.devices.d.detectors['identity-change'].state.allowed = '1,3,6';
  assert.throws(
    () => createEngine({ learnMs: 10_000, tiers: ['T4'] }).importBaseline(bad),
    /allowed/,
  );
  const huge = JSON.parse(JSON.stringify(saved));
  huge.devices.d.detectors['identity-change'].state.allowed = Array.from(
    { length: 5001 },
    (_, i) => `fp-${i}`,
  );
  assert.throws(
    () => createEngine({ learnMs: 10_000, tiers: ['T4'] }).importBaseline(huge),
    /exceeds cap/,
  );
  const odd = JSON.parse(JSON.stringify(saved));
  odd.devices.d.detectors['identity-change'].state.allowed = [1];
  assert.throws(
    () => createEngine({ learnMs: 10_000, tiers: ['T4'] }).importBaseline(odd),
    /must be strings/,
  );
});

test('a second device merges a new MAC into the shared fingerprint table', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  engine.feed(dhcp('aa:bb:cc:dd:ee:01', '1,3,6', 0));
  engine.feed({ ...dhcp('aa:bb:cc:dd:ee:01', '1,3,6', 1), device: 'e' });
  const saved = engine.exportBaseline({ createdAt: 1 });
  saved.devices.e.detectors['identity-change'].state.macs.push(['aa:bb:cc:dd:ee:02', '9,9,9']);
  saved.devices.d.detectors['identity-change'].state.macs.push(['not-a-pair']);
  const broken = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  assert.throws(() => broken.importBaseline(JSON.parse(JSON.stringify(saved))), /pairs/);
  saved.devices.d.detectors['identity-change'].state.macs = [['aa:bb:cc:dd:ee:01', '1,3,6']];
  const next = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  next.importBaseline(saved);
  next.feed(dhcp('aa:bb:cc:dd:ee:01', '1,3,6', 2));
  next.feed({ ...dhcp('aa:bb:cc:dd:ee:02', '9,9,9', 3), device: 'e' });
  const merged = next.exportBaseline({ createdAt: 1 });
  const macs = merged.devices.d.detectors['identity-change'].state.macs;
  assert.ok(macs.some((pair) => pair[0] === 'aa:bb:cc:dd:ee:02'));
});

test('identity-change survives export and import', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  engine.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 0));
  engine.lock('d');
  const copy = createEngine({ learnMs: 10_000, tiers: ['T4'] });
  /** @type {any[]} */
  const alerts = [];
  copy.on('anomaly', (item) => {
    if (item.detector === 'identity-change') alerts.push(item);
  });
  copy.importBaseline(engine.exportBaseline({ createdAt: 1 }));
  copy.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,3,6', 30_000));
  copy.feed(dhcp('aa:bb:cc:dd:ee:ff', '1,15,3,6', 31_000));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].data.previous, '1,3,6');
});
