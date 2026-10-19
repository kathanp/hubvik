'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../src/index.js');

const DAY = 24 * 3600e3;
const NUMERIC = new Set(['gt', 'gte', 'lt']);

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 0,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    ...extra,
  };
}

/**
 * Crafted attacks copied from the detector tests and phase replays.
 * @type {Record<string, (engine: any) => void>}
 */
const ATTACKS = {
  'src-spoof'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 0,
      mac: 'aa',
      msg: 'ack',
      serverIp: '10.0.0.1',
      requestedIp: '10.0.0.8',
    });
    engine.feed(flow({ ts: 1000, srcIp: '192.0.2.9' }));
  },
  'tftp-activity'(engine) {
    engine.feed(flow({ ts: 500, proto: 'udp', dstPort: 69, direction: 'out' }));
  },
  'spam-relay'(engine) {
    for (let i = 0; i < 11; i++) engine.feed(flow({ ts: 600 + i, dstPort: 25 }));
  },
  'rogue-dhcp'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 0,
      mac: 'aa',
      msg: 'ack',
      serverIp: '10.0.0.1',
    });
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 1000,
      mac: 'aa',
      msg: 'offer',
      serverIp: '10.9.9.9',
    });
  },
  'rogue-ra'(engine) {
    engine.feed({
      type: 'ra',
      device: 'r',
      ts: 0,
      srcMac: 'aa',
      srcIp: 'fe80::1',
      prefixes: [],
      routerLifetime: 1800,
    });
    engine.feed({
      type: 'ra',
      device: 'r',
      ts: 1000,
      srcMac: 'bb',
      srcIp: 'fe80::2',
      prefixes: [],
      routerLifetime: 1800,
    });
  },
  'new-device'(engine) {
    engine.feed({ device: 'first', dst: 'a.example', bytes: 1, ts: 0 });
    engine.feed({ device: 'other', dst: 'a.example', bytes: 1, ts: 5000 });
  },
  'clock-jump'(engine) {
    engine.feed(flow({ ts: 100000 }));
    engine.feed(flow({ ts: 0 }));
  },
  'alert-storm'(engine) {
    engine.feed(flow({ ts: 0, dstIp: '1.2.3.4' }));
    engine.feed(flow({ ts: 1000, dstIp: '1.2.3.5' }));
  },
};

/**
 * @param {string} id
 */
const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

function optionsFor(id) {
  /** @type {any} */
  const options = { tiers: TIERS, learnMs: 0 };
  if (id === 'alert-storm') options.detectors = { 'alert-storm': { maxPerMinute: 1 } };
  if (id === 'new-device' || id === 'spam-relay') options.learnMs = 1000;
  if (id === 'clock-jump') options.learnMs = 86400000;
  return options;
}

test('every explaining detector meets the explain contract', () => {
  const covered = Object.values(detectors).filter((det) => det.meta && det.meta.explains === true);
  assert.ok(covered.length > 0);
  for (const det of covered) {
    const fire = ATTACKS[det.id];
    assert.ok(fire, `${det.id} has no crafted attack`);
    const engine = createEngine(optionsFor(det.id));
    /** @type {any[]} */
    const hits = [];
    engine.on('anomaly', (item) => {
      if (item.detector === det.id) hits.push(item);
    });
    engine.on('shadow-anomaly', (item) => {
      if (item.detector === det.id) hits.push(item);
    });
    fire(engine);
    assert.ok(hits.length >= 1, `${det.id} did not fire`);
    const anomaly = hits[0];
    const row = engine.explain(anomaly.id);
    assert.ok(row, `${det.id} explain`);
    assert.ok(row.test, `${det.id} test`);
    assert.ok(row.observed !== undefined && row.observed !== null, `${det.id} observed`);
    assert.ok(
      row.threshold !== undefined || row.learned !== undefined,
      `${det.id} threshold or learned`,
    );
    if (NUMERIC.has(row.test)) {
      assert.strictEqual(row.margin, row.observed / row.threshold, `${det.id} margin`);
    }
    if (det.hardRule) {
      assert.ok(
        Array.isArray(row.suppressWith) && row.suppressWith.length > 0,
        `${det.id} suppress`,
      );
      for (const entry of row.suppressWith) {
        assert.notStrictEqual(entry.method, 'allow', `${det.id} allow`);
        if (
          entry.method === 'suppress' &&
          entry.args[2] &&
          typeof entry.args[2].untilTs === 'number'
        ) {
          assert.ok(entry.args[2].untilTs <= anomaly.ts + DAY, `${det.id} untilTs`);
        }
      }
    }
  }
});
