'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const ZONES = [
  { id: 'a', cidr: '10.1.0.0/16' },
  { id: 'b', cidr: '10.2.0.0/16' },
];

/**
 * @param {Record<string, unknown>} extra
 */
function lan(extra) {
  return {
    type: 'flow',
    device: 'src',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '10.1.0.2',
    dstPort: 80,
    proto: 'tcp',
    direction: 'lan',
    bytesOut: 40,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 10,
    ...extra,
  };
}

/**
 * @param {any} engine
 * @param {string} mac
 * @param {string} ip
 * @param {number} ts
 */
function bind(engine, mac, ip, ts) {
  engine.feed({ type: 'dhcp', device: mac, ts, mac, msg: 'ack', requestedIp: ip });
}

test('graph-new-bridge fires on a zone pair that learning never saw', () => {
  const engine = createEngine({
    shadow: true,
    learnMs: 500,
    tiers: ['T1'],
    identity: 'auto',
    zones: ZONES,
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'graph-new-bridge') hits.push(row);
  });
  bind(engine, 'aa:bb:cc:dd:ee:01', '10.1.0.2', 1);
  bind(engine, 'aa:bb:cc:dd:ee:02', '10.2.0.2', 2);
  engine.feed(lan({ ts: 100 }));
  engine.lock('src');
  engine.feed(lan({ ts: 1000, dstIp: '10.2.0.2' }));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.pair, 'a|b');
});

test('graph-new-bridge stays quiet without zones and caps LAN edges at 32', () => {
  const quiet = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  /** @type {any[]} */
  const hits = [];
  quiet.on('shadow-anomaly', (row) => {
    if (row.detector === 'graph-new-bridge') hits.push(row);
  });
  bind(quiet, 'aa:bb:cc:dd:ee:01', '10.1.0.2', 1);
  bind(quiet, 'aa:bb:cc:dd:ee:02', '10.2.0.2', 2);
  quiet.feed(lan({ ts: 100 }));
  quiet.feed(lan({ ts: 200, dstIp: '10.2.0.2' }));
  quiet.feed(lan({ ts: 300, dstIp: '239.255.255.250', dstPort: 1900, proto: 'udp' }));
  assert.deepStrictEqual(hits, []);

  const capped = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  for (let i = 0; i < 33; i += 1) {
    const ip = `10.3.0.${i + 1}`;
    const mac = `aa:bb:cc:dd:ee:${(i + 1).toString(16).padStart(2, '0')}`;
    bind(capped, mac, ip, i);
    capped.feed(lan({ ts: 1000 + i, dstIp: ip, dstPort: 80 }));
  }
  assert.strictEqual(capped.graph({ device: 'src' }).lan.length, 32);
  const saved = capped.checkpoint({ createdAt: 1 });
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  next.restore(saved);
  assert.strictEqual(next.graph({ device: 'src' }).lan.length, 32);
});

test('graph-new-bridge import rejects a pair list over the cap', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  engine.feed(lan({ ts: 1, direction: 'out', dstIp: '9.9.9.9' }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const pairs = [];
  for (let i = 0; i < 257; i += 1) pairs.push(`a|z${i}`);
  assert.throws(
    () =>
      engine.importBaseline({
        ...saved,
        devices: {
          src: {
            ...saved.devices.src,
            detectors: { 'graph-new-bridge': { v: 1, state: { pairs, fired: false } } },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('graph-new-bridge is silent on the all-tier benign matrix', () => {
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
      const engine = createEngine({
        shadow: true,
        learnMs: 7 * DAY,
        tiers: ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
        identity: 'auto',
      });
      engine.setDeviceClass(events[0].device, profile);
      /** @type {any[]} */
      const hits = [];
      engine.on('shadow-anomaly', (row) => {
        if (
          row.detector === 'graph-new-bridge' &&
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
