'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const IDS = [
  'day-of-week-drift',
  'sni-ip-mismatch',
  'mac-randomization-churn',
  'discovery-spoof',
  'mud-violation',
  'ot-schedule-drift',
  'reverse-shell-shape',
  'llmnr-nbns-poison',
  'dns-answer-mismatch',
];

test('Rel 0.9 shadow detectors are silent on the all-tier benign matrix', () => {
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
        wifi: true,
      });
      const engine = createEngine({
        shadow: true,
        learnMs: 7 * DAY,
        tiers: ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
        identity: 'auto',
      });
      engine.setDeviceClass(events[0].device, profile);
      /** @type {string[]} */
      const hits = [];
      engine.on('shadow-anomaly', (row) => {
        if (IDS.includes(row.detector)) hits.push(`${row.detector}:${profile}`);
      });
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      assert.deepEqual(hits, [], `${profile} seed ${seed}`);
    }
  }
});
