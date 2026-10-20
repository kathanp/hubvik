'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const ID = 'fleet-baseline-poisoning';
const KEY = 'fleet-summary-key';

/**
 * @param {boolean} [shadow]
 */
function box(shadow = true) {
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const id of Object.keys(detectors)) {
    if (id !== ID && id !== 'peer-divergence') off[id] = { enabled: false };
  }
  return createEngine({
    shadow,
    learnMs: 7 * DAY,
    tiers: ['T0'],
    detectors: off,
  });
}

/**
 * @param {any} engine
 * @param {string} device
 * @param {string} dst
 * @param {number} ts
 */
function learn(engine, device, dst, ts) {
  engine.feed({ device, dst, bytes: 10, ts });
  engine.setPeerGroup(device, 'cams');
}

/**
 * @param {string} dst
 * @param {number} [ts]
 */
function summaryFrom(dst, ts = 1_000) {
  const other = box();
  learn(other, 'cam', dst, ts);
  return other.exportSummary({ key: KEY, gatewayId: 'gw-b' });
}

test('fleet-baseline-poisoning fires when an imported family is unknown locally', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.on('anomaly', () => assert.fail('shadow detector emitted anomaly'));
  learn(engine, 'cam', 'cdn.example', 1_000);
  engine.importPeerSummaries([summaryFrom('evil.example')], { verify: KEY });
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].detector, ID);
  assert.strictEqual(found[0].severity, 'high');
  assert.strictEqual(found[0].data.family.length, 16);
});

test('fleet-baseline-poisoning stays quiet for a family a local peer already learned', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  learn(engine, 'cam', 'cdn.example', 1_000);
  engine.importPeerSummaries([summaryFrom('cdn.example')], { verify: KEY });
  assert.deepStrictEqual(found, []);
});

test('fleet-baseline-poisoning stays quiet when no local peer has a family', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.importPeerSummaries([summaryFrom('evil.example')], { verify: KEY });
  assert.deepStrictEqual(found, []);
});

test('fleet-baseline-poisoning ignores a summary older than seven days', () => {
  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  learn(engine, 'cam', 'cdn.example', 8 * DAY);
  engine.importPeerSummaries([summaryFrom('evil.example', 1_000)], { verify: KEY });
  assert.deepStrictEqual(found, []);
});

test('fleet-baseline-poisoning does not run unless shadow selects it', () => {
  const engine = box(false);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.on('anomaly', (row) => found.push(row));
  learn(engine, 'cam', 'cdn.example', 1_000);
  engine.importPeerSummaries([summaryFrom('evil.example')], { verify: KEY });
  assert.deepStrictEqual(found, []);
});

test('fleet-baseline-poisoning rejects a bad signature and a forbidden key', () => {
  const engine = box();
  learn(engine, 'cam', 'cdn.example', 1_000);
  const summary = summaryFrom('evil.example');
  summary.groups[0].families[0] = '0'.repeat(16);
  assert.throws(() => engine.importPeerSummaries([summary], { verify: KEY }), /signature/);
  const poisoned = JSON.parse('{"gatewayId":"gw-b","ts":1000,"groups":[],"__proto__":{"x":1}}');
  assert.throws(() => engine.importPeerSummaries([poisoned], { verify: KEY }), /forbidden key/);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.importPeerSummaries([summaryFrom('evil.example')], { verify: KEY });
  assert.strictEqual(found.length, 1);
});

test('fleet-baseline-poisoning caps compared families and round-trips state', () => {
  const state = detectors[ID].createState();
  const ctx = { options: { severity: 'high' } };
  for (let i = 0; i < 1001; i += 1) {
    detectors[ID].check(state, { family: `f${i}`, ts: i }, ctx);
  }
  assert.strictEqual(state.fired.size, 1000);
  assert.strictEqual(detectors[ID].check(state, { family: 'one-more', ts: 1001 }, ctx), undefined);
  assert.ok(detectors[ID].memoryEstimate(detectors[ID].createState()) <= 2048);

  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  learn(engine, 'cam', 'cdn.example', 1_000);
  engine.importPeerSummaries([summaryFrom('evil.example')], { verify: KEY });
  const saved = engine.exportBaseline({ createdAt: 1 });
  const next = box();
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 1 });
  assert.deepStrictEqual(
    again.devices.cam.detectors[ID].state,
    saved.devices.cam.detectors[ID].state,
  );
  next.on('shadow-anomaly', (row) => found.push(row));
  next.importPeerSummaries([summaryFrom('evil.example')], { verify: KEY });
  assert.strictEqual(found.length, 1);
});

test('fleet-baseline-poisoning is silent on 14-day benign traffic for every device class', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({ profile, days: 14, seed, startTs: T0 });
      const engine = box();
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
