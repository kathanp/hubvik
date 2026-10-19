'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { scenarios } = require('../../../../eval/evasion-holdout/scenarios.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

test('multi-horizon-exfil emits shadow-anomaly on the holdout', () => {
  const scenario = scenarios().find((row) => row.id === 'holdout-exfil-0.85');
  assert.ok(scenario);
  const engine = createEngine({
    learnMs: scenario.events[scenario.learnCount - 1].ts + 1,
    tiers: ['T1'],
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'multi-horizon-exfil') hits.push(row);
  });
  for (const event of scenario.events) engine.feed(event);
  engine.flush(scenario.events[scenario.events.length - 1].ts + 3600e3);
  assert.ok(hits.length >= 1);
  assert.strictEqual(hits[0].severity, 'high');
});

test('multi-horizon-exfil restores and rejects a bad daily sketch on import', () => {
  const scenario = scenarios().find((row) => row.id === 'holdout-exfil-0.85');
  const engine = createEngine({
    learnMs: scenario.events[scenario.learnCount - 1].ts + 1,
    tiers: ['T1'],
  });
  for (let i = 0; i < scenario.learnCount; i += 1) engine.feed(scenario.events[i]);
  const saved = engine.exportBaseline({ createdAt: 1 });
  const id = scenario.events[0].device;
  const next = createEngine({ learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 2 });
  assert.ok(again.devices[id].detectors['multi-horizon-exfil'].state.hourly.count >= 1);
  assert.throws(
    () =>
      next.importBaseline({
        ...saved,
        devices: {
          [id]: {
            ...saved.devices[id],
            detectors: {
              'multi-horizon-exfil': {
                v: 1,
                state: { hourly: { count: 0 }, daily: { p: 2, count: 1, markers: 'nope' } },
              },
            },
          },
        },
      }),
    /p2/,
  );
});

test('multi-horizon-exfil is silent on the all-tier benign matrix', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({
        profile,
        days: 14,
        seed,
        startTs: T0,
        rich: true,
        discovery: true,
        ipv6: true,
      });
      const engine = createEngine({ learnMs: 7 * DAY, tiers: TIERS, identity: 'auto' });
      engine.setDeviceClass(events[0].device, profile);
      /** @type {any[]} */
      const hits = [];
      engine.on('shadow-anomaly', (row) => {
        if (
          row.detector === 'multi-horizon-exfil' &&
          row.severity !== 'low' &&
          row.severity !== 'info'
        ) {
          hits.push(row.detector);
        }
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepStrictEqual(hits, [], `${profile} seed ${seed}`);
    }
  }
});
