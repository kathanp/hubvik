'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES, PROFILES } = require('../../../../test/fixtures/profiles');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * Anomalies emitted while watching, after 7 learned days.
 * @param {string} profile
 * @param {boolean} discovery
 * @returns {{ detector: string, severity: string, ts: number }[]}
 */
function watching(profile, discovery) {
  const learn = simulate({
    profile,
    days: 7,
    seed: 1,
    startTs: T0,
    rich: true,
    discovery: false,
  });
  const engine = createEngine({
    learnMs: 7 * DAY,
    tiers: TIERS,
    detectors: {
      'exploit-probe-http': { enabled: true },
      'young-domain': { enabled: true },
      'ttl-anomaly': { enabled: true },
    },
  });
  engine.setDeviceClass(learn[0].device, profile);
  for (const event of learn) engine.feed(event);
  engine.lock(learn[0].device);
  const more = simulate({
    profile,
    days: 2,
    seed: 1,
    startTs: T0 + 7 * DAY,
    rich: true,
    discovery,
  });
  if (discovery) {
    const spec = PROFILES[profile];
    more.push({
      type: 'flow',
      device: learn[0].device,
      ts: T0 + 7 * DAY + spec.hours[0] * H + 9_000,
      srcIp: '192.0.2.10',
      srcPort: 5353,
      dstIp: 'ff02::fb',
      dstPort: 5353,
      proto: 'udp',
      direction: 'lan',
      bytesOut: 80,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 1,
      ttl: 255,
    });
    more.sort((a, b) => a.ts - b.ts);
  }
  /** @type {{ detector: string, severity: string, ts: number }[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => {
    anomalies.push({ detector: item.detector, severity: item.severity, ts: item.ts });
  });
  for (const event of more) engine.feed(event);
  engine.flush(T0 + 9 * DAY);
  return anomalies;
}

test('discovery flows cause no anomaly at any severity', () => {
  for (const profile of CLASS_NAMES) {
    const quiet = watching(profile, false);
    const noisy = watching(profile, true);
    assert.deepStrictEqual(noisy, quiet, profile);
  }
});
