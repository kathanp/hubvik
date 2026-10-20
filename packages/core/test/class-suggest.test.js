'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../src/index.js');
const CONFIDENCE = require('../src/data/confidence.json');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

const TOP = {
  camera: 'camera',
  thermostat: 'thermostat',
  'hvac-controller': 'hvac-controller',
};

test('simulator profiles suggest their own class and never a wrong class at 0.7', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({ profile, days: 1, seed, startTs: T0, rich: true });
      const engine = createEngine({
        classSuggest: true,
        learnMs: 7 * DAY,
        tiers: ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
        browserJa4: ['t13d1516h2_8daaf6152771_vendor'],
      });
      for (const event of events) engine.feed(event);
      const rows = engine.stats().classSuggestions[events[0].device] || [];
      if (TOP[profile]) {
        assert.strictEqual(rows[0] && rows[0].class, TOP[profile], `${profile} seed ${seed}`);
      }
      for (const row of rows) {
        if (row.score >= 0.7) assert.strictEqual(row.class, profile, `${profile} seed ${seed}`);
      }
    }
  }
});

test('listen ports, browser families, and a small MQTT publish suggest the spec class', () => {
  const engine = createEngine({
    classSuggest: true,
    learnMs: 7 * DAY,
    tiers: ['T0', 'T1', 'T2', 'T3', 'T5'],
    browserJa4: ['browser-ja4'],
  });
  engine.feed(flow('printer-1', 631));
  engine.feed(flow('nas-1', 445));
  for (let i = 0; i < 31; i += 1) {
    engine.feed({
      type: 'dns',
      device: 'smart-tv-1',
      ts: 1_000 + i,
      qname: `h${i}.example`,
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '192.0.2.53',
      answers: [{ type: 'A', value: '192.0.2.10', ttl: 60 }],
    });
  }
  engine.feed({
    type: 'tls',
    device: 'smart-tv-1',
    ts: 2_000,
    dstIp: '192.0.2.10',
    dstPort: 443,
    sni: 'h0.example',
    ja4: 'browser-ja4',
    version: 'TLSv1.3',
  });
  engine.feed({
    type: 'app',
    device: 'stat-1',
    ts: 1_000,
    proto: 'mqtt',
    role: 'client',
    peerIp: '192.0.2.20',
    op: 'PUBLISH',
    target: 'home/status',
    result: 'ok',
  });
  const stats = engine.stats().classSuggestions;
  assert.strictEqual(stats['printer-1'][0].class, 'printer');
  assert.strictEqual(stats['nas-1'][0].class, 'nas');
  assert.strictEqual(stats['smart-tv-1'][0].class, 'smart-tv');
  assert.strictEqual(stats['stat-1'][0].class, 'thermostat');
  engine.feed({
    type: 'app',
    device: 'stat-1',
    ts: 1_100,
    proto: 'mqtt',
    role: 'client',
    peerIp: '192.0.2.20',
    op: 'SUBSCRIBE',
    target: 'home/status',
    result: 'ok',
  });
  assert.strictEqual(engine.stats().classSuggestions['stat-1'], undefined);
});

test('a chatty hour does not suggest a thermostat', () => {
  const engine = createEngine({
    classSuggest: true,
    learnMs: 7 * DAY,
    tiers: ['T1', 'T5'],
  });
  engine.feed(flow('cam', 443, { direction: 'out', bytesOut: 60_000 }));
  engine.feed({
    type: 'app',
    device: 'cam',
    ts: 1_000,
    proto: 'mqtt',
    role: 'client',
    peerIp: '192.0.2.20',
    op: 'PUBLISH',
    target: 'up',
    result: 'ok',
  });
  const rows = engine.stats().classSuggestions.cam || [];
  assert.ok(!rows.some((row) => row.class === 'thermostat'));
});

test('calibrated confidence uses the constant table when a detector sets no margin', () => {
  const engine = createEngine({
    calibratedConfidence: true,
    learnMs: 0,
    tiers: ['T0'],
    detectors: Object.fromEntries(
      Object.keys(detectors).map((id) => [id, { enabled: id === 'new-destination' }]),
    ),
  });
  /** @type {any[]} */
  const found = [];
  engine.on('anomaly', (row) => found.push(row));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 2_000 });
  assert.ok(found.length > 0);
  assert.strictEqual(found[0].confidence, CONFIDENCE['new-destination']);
});

/**
 * @param {string} device
 * @param {number} dstPort
 * @param {{ direction?: string, bytesOut?: number }} [extra]
 */
function flow(device, dstPort, extra = {}) {
  return {
    type: 'flow',
    device,
    ts: 1_000,
    srcIp: '192.0.2.20',
    srcPort: 40000,
    dstIp: '192.0.2.10',
    dstPort,
    proto: 'tcp',
    direction: extra.direction || 'in',
    bytesOut: extra.bytesOut || 100,
    bytesIn: 100,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
  };
}
