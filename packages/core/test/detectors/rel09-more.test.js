'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');

/**
 * @param {string} id
 * @param {string[]} tiers
 */
function box(id, tiers) {
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const other of Object.keys(detectors)) if (other !== id) off[other] = { enabled: false };
  return createEngine({ shadow: true, learnMs: 0, tiers, detectors: off });
}

test('mac-randomization-churn reports five MACs for one fingerprint', () => {
  const engine = box('mac-randomization-churn', ['T0', 'T4']);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  for (let i = 0; i < 5; i += 1) {
    engine.feed({
      type: 'dhcp',
      device: 'lan',
      ts: 1_000 + i,
      mac: `aa:bb:cc:dd:ee:0${i}`,
      msg: 'request',
      fingerprint: '1,3,6',
    });
  }
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].severity, 'info');
  const det = detectors['mac-randomization-churn'];
  const dev = det.createState();
  det.importState(dev, {
    prints: [
      null,
      { fingerprint: 1, macs: [] },
      { fingerprint: 'ok', macs: [{ mac: 'a', ts: 1 }] },
    ],
  });
  assert.strictEqual(dev.prints.size, 1);
  assert.ok(det.memoryEstimate(dev) > 0);
  const crowded = box('mac-randomization-churn', ['T0', 'T4']);
  for (let i = 0; i < 257; i += 1) {
    crowded.feed({
      type: 'dhcp',
      device: 'lan',
      ts: 1_000 + i,
      mac: 'aa:bb:cc:dd:ee:01',
      msg: 'request',
      fingerprint: `fp-${i}`,
    });
  }
  const prints = crowded.exportBaseline({ createdAt: 1 }).devices.lan.detectors[
    'mac-randomization-churn'
  ].state.prints;
  assert.strictEqual(prints.length, 256);
  assert.ok(!prints.some((row) => row.fingerprint === 'fp-0'));
});

test('discovery-spoof fires when a second MAC claims a name', () => {
  const engine = box('discovery-spoof', ['T0', 'T4']);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  const base = {
    type: 'discovery',
    device: 'lan',
    ts: 1_000,
    proto: 'ssdp',
    srcIp: '192.0.2.10',
    direction: 'lan',
  };
  engine.feed({ ...base, name: 'cam', mac: 'aa:bb:cc:dd:ee:01' });
  engine.feed({ ...base, ts: 2_000, name: 'cam', mac: 'aa:bb:cc:dd:ee:02' });
  assert.strictEqual(found.length, 1);
});

test('ot-schedule-drift fires on a write outside the learned hours', () => {
  const engine = createEngine({
    shadow: true,
    learnMs: 86_400_000,
    tiers: ['T0', 'T5'],
    detectors: Object.fromEntries(
      Object.keys(detectors)
        .filter((id) => id !== 'ot-schedule-drift')
        .map((id) => [id, { enabled: false }]),
    ),
  });
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  for (let hour = 0; hour < 4; hour += 1) {
    engine.feed({
      type: 'app',
      device: 'hvac',
      ts: hour * 3_600_000,
      proto: 'bacnet',
      role: 'client',
      peerIp: '192.0.2.20',
      op: 'WriteProperty',
    });
  }
  engine.lock('hvac');
  engine.feed({
    type: 'app',
    device: 'hvac',
    ts: 10 * 3_600_000,
    proto: 'bacnet',
    role: 'client',
    peerIp: '192.0.2.20',
    op: 'WriteProperty',
  });
  assert.strictEqual(found.length, 1);
});
