'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, SEVERITY } = require('../src/index.js');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

test('14 benign days on every tier stay under medium', () => {
  /** @type {string[]} */
  const lows = [];
  /** @type {string[]} */
  const shadowMedium = [];
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({
        profile,
        days: 14,
        seed,
        startTs: T0,
        rich: true,
        discovery: true,
      });
      const engine = createEngine({
        shadow: true,
        learnMs: 7 * DAY,
        tiers: TIERS,
        detectors: {
          'exploit-probe-http': { enabled: true },
          'young-domain': { enabled: true },
          'ttl-anomaly': { enabled: true },
        },
      });
      engine.loadIndicators(
        [1, 2, 3, 4, 5].map((n) => ({
          value: `fresh-example-${n}.test`,
          type: 'young-domain',
          source: 'lab',
          confidence: 0.8,
          expiresTs: T0 + 400 * DAY,
        })),
      );
      engine.setDeviceClass(events[0].device, profile);
      /** @type {any[]} */
      const anomalies = [];
      /** @type {any[]} */
      const learning = [];
      engine.on('anomaly', (item) => anomalies.push(item));
      engine.on('shadow-anomaly', (item) => {
        if (SEVERITY[item.severity] >= SEVERITY.medium) {
          shadowMedium.push(`${profile} seed ${seed} ${item.detector} ${item.severity}`);
        }
      });
      engine.on('warning', (warning) => {
        if (warning.code === 'SUSPICIOUS_LEARNING') learning.push(warning);
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepStrictEqual(learning, [], `${profile} seed ${seed}`);
      for (const item of anomalies) {
        if (SEVERITY[item.severity] < SEVERITY.medium) {
          lows.push(`${profile} seed ${seed} ${item.detector} ${item.severity}`);
        }
      }
      const medium = anomalies.filter((item) => SEVERITY[item.severity] >= SEVERITY.medium);
      assert.deepStrictEqual(
        medium.map((item) => `${item.detector}:${item.actual}`),
        [],
        `${profile} seed ${seed}`,
      );
    }
  }
  console.log(lows.length ? lows.join('\n') : 'low/info anomalies: none');
  assert.deepStrictEqual(shadowMedium, []);
});
