'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const ID = 'peer-divergence-federated';

/**
 * @param {number} [learnMs]
 */
function box(learnMs = 0) {
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const id of Object.keys(detectors)) if (id !== ID) off[id] = { enabled: false };
  return createEngine({ shadow: true, learnMs, tiers: ['T0'], detectors: off });
}

/**
 * @param {string[][]} rows
 * @param {number} [ts]
 */
function summaries(rows, ts = 1_000) {
  return rows.map((families, index) => ({
    gatewayId: `gw-${index}`,
    ts,
    groups: [{ id: `g-${index}`, families, ports: [], hll: { p: 10, count: families.length } }],
  }));
}

test('peer-divergence-federated fires when fewer than half the gateways share the family', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.on('anomaly', () => assert.fail('shadow detector emitted anomaly'));
  engine.importPeerSummaries(summaries([[], [], []]));
  engine.feed({ device: 'cam', dst: 'onlyhere.example', bytes: 10, ts: 1_000 });
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].detector, ID);
  assert.strictEqual(found[0].severity, 'high');
  assert.strictEqual(found[0].data.family, 'onlyhere.example');
  assert.strictEqual(found[0].data.have, 0);
});

test('peer-divergence-federated stays quiet when half the summaries share the family', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  const family = 'onlyhere.example';
  engine.importPeerSummaries(summaries([[family], [family], []]));
  engine.feed({ device: 'cam', dst: family, bytes: 10, ts: 1_000 });
  assert.deepStrictEqual(found, []);
});

test('peer-divergence-federated counts a local peer toward the majority', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  const family = 'onlyhere.example';
  engine.feed({ device: 'other', dst: family, bytes: 10, ts: 1_000 });
  engine.setPeerGroup('other', 'cams');
  engine.setPeerGroup('cam', 'cams');
  engine.importPeerSummaries(summaries([[family], [], []]));
  engine.feed({ device: 'cam', dst: family, bytes: 10, ts: 2_000 });
  assert.deepStrictEqual(found, []);
});

test('peer-divergence-federated stays quiet with fewer than three gateways', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.importPeerSummaries(summaries([[], []]));
  engine.feed({ device: 'cam', dst: 'onlyhere.example', bytes: 10, ts: 1_000 });
  assert.deepStrictEqual(found, []);
});

test('peer-divergence-federated waits until watching and ignores a stale summary', () => {
  const engine = box(30 * DAY);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed({ device: 'cam', dst: 'cdn.example', bytes: 10, ts: 8 * DAY });
  engine.importPeerSummaries(summaries([[], [], []], 1_000));
  engine.feed({ device: 'cam', dst: 'onlyhere.example', bytes: 10, ts: 8 * DAY + 1 });
  assert.deepStrictEqual(found, []);
  engine.lock('cam');
  engine.importPeerSummaries(summaries([[], [], []], 8 * DAY));
  engine.feed({ device: 'cam', dst: 'fresh.example', bytes: 10, ts: 8 * DAY + 2 });
  assert.strictEqual(found.length, 1);
});

test('peer-divergence-federated caps families and round-trips fired state', () => {
  const engine = box();
  for (let i = 0; i < 70; i += 1) {
    engine.feed({ device: 'cam', dst: `h${i}.example`, bytes: 10, ts: 1_000 + i });
  }
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.ok(saved.devices.cam.detectors[ID].state.families.length <= 64);
  assert.ok(detectors[ID].memoryEstimate(detectors[ID].createState()) <= 2048);

  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.importPeerSummaries(summaries([[], [], []]));
  engine.feed({ device: 'cam', dst: 'newname.example', bytes: 10, ts: 2_000 });
  assert.strictEqual(found.length, 1);
  const round = engine.exportBaseline({ createdAt: 1 });
  const next = box();
  next.importBaseline(round);
  next.importPeerSummaries(summaries([[], [], []]));
  next.on('shadow-anomaly', (row) => found.push(row));
  next.feed({ device: 'cam', dst: 'newname.example', bytes: 10, ts: 3_000 });
  assert.strictEqual(found.length, 1);
});

test('peer-divergence-federated is silent on 14-day benign traffic for every device class', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({ profile, days: 14, seed, startTs: T0 });
      const engine = box(7 * DAY);
      engine.setDeviceClass(events[0].device, profile);
      /** @type {string[]} */
      const hits = [];
      engine.on('shadow-anomaly', (row) => {
        if (row.detector === ID) hits.push(row.detector);
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepEqual(hits, [], `${profile} seed ${seed}`);
    }
  }
});
