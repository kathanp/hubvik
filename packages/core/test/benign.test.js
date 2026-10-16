'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

test('14 benign days produce no anomalies for every device class', () => {
  for (const profile of CLASS_NAMES) {
    const events = simulate({ profile, days: 14, seed: 7, startTs: T0 });
    const engine = createEngine({ learnMs: 7 * DAY });
    const anomalies = [];
    engine.on('anomaly', (item) => anomalies.push(item));
    for (const event of events) engine.feed(event);
    engine.flush(T0 + 14 * DAY);
    assert.deepStrictEqual(
      anomalies,
      [],
      `${profile} raised ${anomalies.map((item) => item.detector).join(',')}`,
    );
  }
});
