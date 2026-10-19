'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

/**
 * @param {any} engine
 * @param {number} n
 * @param {number} ts
 */
function inbound(engine, n, ts) {
  for (let i = 0; i < n; i += 1) {
    engine.feed({
      type: 'flow',
      device: `peer-${i}`,
      ts: ts + i,
      srcIp: `10.0.1.${i + 1}`,
      srcPort: 40000,
      dstIp: '10.0.0.10',
      dstPort: 80,
      proto: 'tcp',
      direction: 'lan',
      bytesOut: 20,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
    });
  }
}

test('graph-role-change fires when a quiet device gains five LAN clients', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  engine.feed({
    type: 'dhcp',
    device: 'aa:bb:cc:dd:ee:10',
    ts: 1,
    mac: 'aa:bb:cc:dd:ee:10',
    msg: 'ack',
    requestedIp: '10.0.0.10',
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'graph-role-change') hits.push(row);
  });
  inbound(engine, 5, 1000);
  engine.flush(60_000);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].device, 'aa:bb:cc:dd:ee:10');
  assert.strictEqual(hits[0].severity, 'high');

  const hub = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  hub.setDeviceClass('aa:bb:cc:dd:ee:10', 'hub');
  hub.feed({
    type: 'dhcp',
    device: 'aa:bb:cc:dd:ee:10',
    ts: 1,
    mac: 'aa:bb:cc:dd:ee:10',
    msg: 'ack',
    requestedIp: '10.0.0.10',
  });
  /** @type {any[]} */
  const skipped = [];
  hub.on('shadow-anomaly', (row) => {
    if (row.detector === 'graph-role-change') skipped.push(row);
  });
  inbound(hub, 5, 1000);
  hub.flush(60_000);
  assert.deepStrictEqual(skipped, []);
});

test('graph-role-change restores the learned max in-degree', () => {
  const engine = createEngine({ shadow: true, learnMs: 10_000, tiers: ['T1'], identity: 'auto' });
  engine.feed({
    type: 'dhcp',
    device: 'aa:bb:cc:dd:ee:10',
    ts: 1,
    mac: 'aa:bb:cc:dd:ee:10',
    msg: 'ack',
    requestedIp: '10.0.0.10',
  });
  inbound(engine, 1, 1000);
  engine.flush(60_000);
  const saved = engine.exportBaseline({ createdAt: 1 });
  const state = saved.devices['aa:bb:cc:dd:ee:10'].detectors['graph-role-change'].state;
  assert.strictEqual(state.learnedMax, 1);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 2 });
  assert.strictEqual(
    again.devices['aa:bb:cc:dd:ee:10'].detectors['graph-role-change'].state.learnedMax,
    1,
  );
});

test('graph-role-change is silent on the all-tier benign matrix', () => {
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
          row.detector === 'graph-role-change' &&
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
