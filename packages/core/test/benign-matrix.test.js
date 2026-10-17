'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, SEVERITY } = require('../src/index.js');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

test('14 benign days and 3 seeds produce no anomaly at medium or above', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({ profile, days: 14, seed, startTs: T0 });
      const engine = createEngine({ learnMs: 7 * DAY });
      /** @type {any[]} */
      const anomalies = [];
      /** @type {any[]} */
      const learning = [];
      engine.on('anomaly', (item) => anomalies.push(item));
      engine.on('warning', (warning) => {
        if (warning.code === 'SUSPICIOUS_LEARNING') learning.push(warning);
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepStrictEqual(learning, [], `${profile} seed ${seed}`);
      const medium = anomalies.filter((item) => SEVERITY[item.severity] >= SEVERITY.medium);
      assert.deepStrictEqual(
        medium,
        [],
        `${profile} seed ${seed}: ${medium.map((item) => item.detector).join(',')}`,
      );
    }
  }
});
