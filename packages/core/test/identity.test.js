'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, SEVERITY } = require('../src/index.js');
const { simulate } = require('../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../test/fixtures/clock');

const MAC = 'aa:bb:cc:dd:ee:10';
const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {number} day
 */
function rotation(day) {
  const ip = `2001:db8:${day}::1`;
  const ts = day * DAY;
  return [
    { type: 'nd', device: MAC, ts, ip, mac: MAC, op: 'na' },
    { device: ip, dst: 'video.vendor.com', bytes: 100, ts: ts + 1 },
  ];
}

test('a rotating IPv6 address stays one device when identity is auto', () => {
  const auto = createEngine({ learnMs: DAY, identity: 'auto', tiers: ['T0', 'T1', 'T4'] });
  /** @type {any[]} */
  const quiet = [];
  auto.on('anomaly', (item) => quiet.push(item));
  for (let day = 0; day < 14; day++) {
    for (const event of rotation(day)) auto.feed(event);
  }
  const named = quiet.filter(
    (item) => item.detector === 'new-device' || item.detector === 'new-destination',
  );
  assert.deepStrictEqual(named, []);
  assert.strictEqual(auto.resolve('2001:db8:13::1'), MAC);
  assert.ok(auto.stats().identity.rekeyed > 0);

  const off = createEngine({ learnMs: DAY, identity: 'off', tiers: ['T0', 'T1', 'T4'] });
  /** @type {any[]} */
  const noise = [];
  off.on('anomaly', (item) => noise.push(item));
  for (let day = 0; day < 14; day++) {
    for (const event of rotation(day)) off.feed(event);
  }
  const avoided = noise.filter(
    (item) => item.detector === 'new-device' || item.detector === 'new-destination',
  );
  console.log(`identity off, rotation noise: ${avoided.length}`);
});

test('sixteen addresses per MAC, and a checkpoint keeps the table', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T4'], identity: 'auto' });
  for (let i = 0; i < 17; i++) {
    engine.feed({
      type: 'nd',
      device: MAC,
      ts: i,
      ip: `2001:db8:1::${i + 1}`,
      mac: MAC,
      op: 'na',
    });
  }
  assert.strictEqual(engine.resolve('2001:db8:1::1'), null);
  assert.strictEqual(engine.resolve('2001:db8:1::11'), MAC);
  assert.ok(engine.stats().identity.rows <= 16);
  const saved = engine.checkpoint({ createdAt: 1 });
  const next = createEngine({ learnMs: 0, tiers: ['T4'], identity: 'auto' });
  next.restore(saved);
  assert.strictEqual(next.resolve('2001:db8:1::11'), MAC);
  const body = JSON.parse(JSON.stringify(saved));
  const rows = body.scratch.identity.map;
  while (rows.length < 50001) {
    rows.push([`2001:db8:9::${rows.length}`, { mac: MAC, source: 'nd', lastTs: 1 }]);
  }
  assert.throws(() => next.restore(body), /exceeds cap/);
});

test('dhcp v6 fields bind an address', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T4'] });
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 1,
    mac: MAC,
    msg: 'ack',
    v6: true,
    duid: '00:01:02',
    iaid: 7,
    requestedIp: '2001:db8::9',
  });
  assert.strictEqual(engine.resolve('2001:db8::9'), MAC);
});

test('both benign matrices stay under medium with identity auto and ipv6', () => {
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      for (const rich of [false, true]) {
        const events = simulate({
          profile,
          days: 14,
          seed,
          startTs: T0,
          rich,
          discovery: rich,
          ipv6: true,
        });
        const engine = createEngine({
          learnMs: 7 * DAY,
          identity: 'auto',
          tiers: rich ? TIERS : ['T0'],
        });
        if (rich) engine.setDeviceClass(events[0].device, profile);
        /** @type {any[]} */
        const anomalies = [];
        engine.on('anomaly', (item) => anomalies.push(item));
        for (const event of events) engine.feed(event);
        engine.flush(T0 + 14 * DAY);
        const medium = anomalies.filter((item) => SEVERITY[item.severity] >= SEVERITY.medium);
        assert.deepStrictEqual(
          medium.map((item) => item.detector),
          [],
          `${profile} seed ${seed} rich ${rich}`,
        );
      }
    }
  }
});
