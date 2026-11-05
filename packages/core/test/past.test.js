'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine, HubvikError } = require('../src/index.js');

/**
 * @param {import('../src/index.js').Engine} engine
 */
function once(engine) {
  engine.use({
    id: 'past-demo',
    version: 1,
    requires: ['T0'],
    hardRule: true,
    defaults: { severity: 'low' },
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
      return {
        severity: 'low',
        confidence: 0.8,
        ts: ev.ts,
        actual: `talked to ${ev.dst}`,
        expected: 'a known host',
      };
    },
  });
}

test('at, story, and drill read the past and the live engine emits nothing', () => {
  const engine = createEngine({ learnMs: 7 * 24 * 3600e3, tiers: ['T0'] });
  once(engine);
  /** @type {string[]} */
  const fired = [];
  engine.on('anomaly', (item) => fired.push(item.detector));
  engine.feed({
    type: 'volume-mounted',
    device: 'cam',
    ts: 500,
    name: 'backup',
  });
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  assert.deepStrictEqual(fired, ['past-demo']);
  const seen = engine.at('cam', 1_000);
  assert.strictEqual(seen.source, 'checkpoint');
  assert.strictEqual(seen.device, 'cam');
  assert.strictEqual(seen.mode, 'learning');
  assert.strictEqual(seen.incident.detectors[0], 'past-demo');
  assert.throws(
    () => engine.at('cam', 100),
    (err) => err instanceof HubvikError && err.code === 'AT_LOG_IS_REQUIRED',
  );
  const replay = engine.at('cam', 1_000, {
    log: [{ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 }],
  });
  assert.strictEqual(replay.source, 'checkpoint+log');
  assert.strictEqual(replay.device, 'cam');
  const story = engine.story(seen.incident.id);
  assert.match(story.text, /Earliest host fact: volume-mounted backup at 500/);
  assert.match(story.text, /past-demo: talked to a\.example/);
  const plain = createEngine({ learnMs: 0, tiers: ['T0'] });
  plain.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  const before = plain.anomalyCount;
  const drilled = plain.drill();
  assert.strictEqual(plain.anomalyCount, before);
  assert.strictEqual(fired.length, 1);
  assert.ok(drilled.length >= 1);
  assert.ok(drilled.every((row) => typeof row.scenario === 'string'));
  assert.throws(
    () => engine.feed({ type: 'file-fetched', device: 'cam', ts: 2, name: 1 }),
    (err) => err instanceof HubvikError && err.code === 'HOST_FACT_NAME_IS_INVALID',
  );
  assert.throws(
    () => engine.story('missing'),
    (err) => err instanceof HubvikError && err.code === 'STORY_INCIDENT_IS_INVALID',
  );
  assert.throws(
    () => engine.at('cam', Number.NaN),
    (err) => err instanceof HubvikError && err.code === 'AT_TS_IS_INVALID',
  );
});

test('without lists the alert that stays quiet once the destination is learned', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  const events = [{ device: 'cam', dst: 'new.example', bytes: 10, ts: 1_000 }];
  const result = engine.without('cam', 'new.example', events);
  assert.strictEqual(engine.anomalyCount, 0);
  assert.ok(result.quiet.some((row) => row.detector === 'new-destination'));
  assert.throws(
    () => engine.without('cam', 'new.example', null),
    (err) => err instanceof HubvikError && err.code === 'WITHOUT_EVENTS_ARE_INVALID',
  );
});

test('diffBaseline lists destinations that appeared and disappeared', () => {
  const before = {
    devices: {
      cam: {
        detectors: { 'new-destination': { state: { dsts: ['a.example'] } } },
        suggestions: ['bulb'],
      },
    },
  };
  const after = {
    devices: {
      cam: {
        detectors: { 'new-destination': { state: { dsts: ['b.example'] } } },
        suggestions: ['camera'],
      },
    },
  };
  const diff = createEngine().diffBaseline(before, after);
  assert.deepStrictEqual(diff.devices[0].destinations, {
    appeared: ['b.example'],
    disappeared: ['a.example'],
  });
  assert.deepStrictEqual(diff.devices[0].suggestions, {
    appeared: ['camera'],
    disappeared: ['bulb'],
  });
  assert.throws(
    () => createEngine().diffBaseline(null, after),
    (err) => err instanceof HubvikError && err.code === 'DIFF_BASELINE_IS_INVALID',
  );
});

test('a sharded engine can read at for a device it has seen', () => {
  const engine = createShardedEngine({
    learnMs: 7 * 24 * 3600e3,
    shards: 2,
    inline: true,
    tiers: ['T0'],
  });
  engine.feed({ device: 'cam', dst: 'a.example', bytes: 10, ts: 1_000 });
  const seen = engine.at('cam', 1_000);
  assert.strictEqual(seen.device, 'cam');
  assert.strictEqual(seen.source, 'checkpoint');
});
