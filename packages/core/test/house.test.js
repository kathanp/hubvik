'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine, HubvikError } = require('../src/index.js');

/**
 * @param {import('../src/index.js').Engine} engine
 * @param {string} id
 * @param {string} severity
 */
function once(engine, id, severity) {
  engine.use({
    id,
    version: 1,
    requires: ['T0'],
    hardRule: true,
    defaults: { severity },
    createState() {
      return { done: false };
    },
    /**
     * @param {{ done: boolean }} state
     * @param {any} ev
     */
    check(state, ev) {
      if (state.done) return null;
      state.done = true;
      const level = ev.device === 'lock' ? 'high' : severity;
      return {
        severity: level,
        confidence: 0.8,
        ts: ev.ts,
        actual: `talked to ${ev.dst}`,
        expected: 'a known host',
        data: { dst: ev.dst },
      };
    },
  });
}

test('house, attention, timeline, and changes read stored facts and emit nothing', () => {
  const engine = createEngine({
    learnMs: 7 * 24 * 3600e3,
    explainCap: 10,
    incidentWindowMs: 1_000,
  });
  once(engine, 'rank-demo', 'low');
  /** @type {string[]} */
  const fired = [];
  engine.on('anomaly', (item) => fired.push(item.detector));
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  engine.feed({ device: 'lock', dst: 'b.example', bytes: 10, ts: 2_000 });
  engine.feed({ device: 'bell', dst: 'c.example', bytes: 10, ts: 3_000 });
  const before = fired.length;
  const house = engine.house(3_000);
  const attention = engine.attention(3_000);
  const timeline = engine.timeline(0);
  const changes = engine.changes(0);
  assert.strictEqual(fired.length, before);
  assert.strictEqual(house.now, 3_000);
  assert.strictEqual(house.devices.length, 3);
  const cam = house.devices.find((row) => row.device === 'cam');
  assert.ok(cam);
  assert.strictEqual(cam.learning, true);
  assert.strictEqual(cam.class, null);
  assert.strictEqual(cam.quiet, false);
  assert.strictEqual(cam.lastSeen, 1_000);
  assert.match(cam.sentence, /talked to a\.example/);
  assert.strictEqual(cam.advice, null);
  assert.ok(cam.readiness);
  assert.strictEqual(cam.readiness.score, 0);
  assert.ok(Array.isArray(house.blind));
  assert.strictEqual(attention.items[0].severity, 'high');
  assert.strictEqual(attention.items[0].device, 'lock');
  assert.ok(timeline.events.some((row) => row.kind === 'device-seen' && row.device === 'cam'));
  assert.ok(timeline.events.some((row) => row.kind === 'incident-opened' && row.device === 'bell'));
  assert.ok(
    timeline.events.some((row) => row.kind === 'wave-started' && row.detector === 'rank-demo'),
  );
  assert.deepStrictEqual(changes.devicesFirstSeen, ['bell', 'cam', 'lock']);
  assert.deepStrictEqual(changes.devicesQuiet, []);
  assert.ok(changes.incidentsOpened.includes('cam'));
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 5_000 });
  const later = engine.changes(0);
  assert.ok(later.incidentsClosed.includes('cam'));
  const quiet = engine.house(5_000, 1_000);
  assert.strictEqual(quiet.devices.find((row) => row.device === 'cam').quiet, false);
  assert.strictEqual(quiet.devices.find((row) => row.device === 'bell').quiet, true);
  assert.strictEqual(
    engine.timeline(0, 1_000).events.some((row) => row.kind === 'device-quiet'),
    true,
  );
  assert.throws(
    () => engine.house(Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'HOUSE_NOW_IS_INVALID',
  );
  assert.throws(
    () => engine.house(0, -1),
    (err) => err instanceof HubvikError && err.code === 'HOUSE_QUIET_IS_INVALID',
  );
  assert.throws(
    () => engine.attention(Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'ATTENTION_NOW_IS_INVALID',
  );
  assert.throws(
    () => engine.timeline(Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'TIMELINE_SINCE_IS_INVALID',
  );
  assert.throws(
    () => engine.changes(Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'CHANGES_SINCE_IS_INVALID',
  );
  assert.throws(
    () => engine.timeline(0, -1),
    (err) => err instanceof HubvikError && err.code === 'TIMELINE_QUIET_IS_INVALID',
  );
  assert.throws(
    () => engine.changes(0, -1),
    (err) => err instanceof HubvikError && err.code === 'CHANGES_QUIET_IS_INVALID',
  );
});

test('house reports the top class suggestion and does not assign the class', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3, classSuggest: true, tiers: ['T0'] });
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  const device = engine.devices.get('cam');
  device.classScores = { bulb: 0.2, camera: 0.9 };
  const row = engine.house(1_000).devices[0];
  assert.strictEqual(row.class, null);
  assert.deepStrictEqual(row.suggestion, { class: 'camera', score: 0.9 });
});

test('the household lists stop at explainCap', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3, explainCap: 1 });
  once(engine, 'low-demo', 'low');
  engine.feed({ device: 'b', dst: 'a.example', bytes: 10, ts: 1_000 });
  engine.feed({ device: 'a', dst: 'b.example', bytes: 10, ts: 2_000 });
  assert.strictEqual(engine.house(2_000).devices.length, 1);
  assert.strictEqual(engine.house(2_000).devices[0].device, 'a');
  assert.strictEqual(engine.attention(2_000).items.length, 1);
  assert.strictEqual(engine.timeline(0).events.length, 1);
  assert.strictEqual(engine.changes(0).devicesFirstSeen.length, 1);
});

test('a sharded engine returns the same household device', () => {
  const engine = createShardedEngine({
    learnMs: 7 * 24 * 3600e3,
    shards: 2,
    inline: true,
    tiers: ['T0'],
  });
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  const house = engine.house(1_000);
  assert.strictEqual(house.devices.length, 1);
  assert.strictEqual(house.devices[0].device, 'cam');
  assert.ok(
    engine.timeline(0).events.some((row) => row.kind === 'device-seen' && row.device === 'cam'),
  );
  assert.deepStrictEqual(engine.changes(0).devicesFirstSeen, ['cam']);
});

test('house still names a device after checkpoint restore', () => {
  const opts = { learnMs: 7 * 24 * 3600e3, tiers: ['T0'] };
  const engine = createEngine(opts);
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  const saved = engine.checkpoint({ createdAt: 1 });
  const restored = createEngine(opts);
  restored.restore(saved);
  const house = restored.house(1_000);
  assert.strictEqual(house.devices[0].device, 'cam');
  assert.strictEqual(house.devices[0].class, null);
});
