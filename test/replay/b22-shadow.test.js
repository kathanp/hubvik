'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEngine } = require('hubvik');
const { flow } = require('../fixtures/flow');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const DAY = 24 * 60 * 60 * 1000;

/**
 * @param {string} id
 * @param {Record<string, unknown>} [extra]
 */
function watch(id, extra = {}) {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: TIERS, ...extra });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === id) hits.push(row);
  });
  return { engine, hits };
}

test('replay: DHCP option 121 default route', () => {
  const { engine, hits } = watch('dhcp-route-injection', { learnMs: 5_000 });
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 1_000,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'offer',
    serverIp: '192.0.2.1',
    options: [53, 1],
  });
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 6_000,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'ack',
    serverIp: '192.0.2.1',
    options: [121],
    routes: ['0.0.0.0/0'],
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
});

test('replay: WPAD name starts answering', () => {
  const { engine, hits } = watch('wpad-hijack', { learnMs: 5_000 });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'wpad.vendor.com',
    qtype: 'A',
    rcode: 'NXDOMAIN',
    resolver: '192.0.2.1',
  });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 6_000,
    qname: 'wpad.vendor.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
    answers: [{ type: 'A', value: '198.51.100.9', ttl: 30 }],
  });
  assert.equal(hits.length, 1);
});

test('replay: router advertisement flood', () => {
  const { engine, hits } = watch('ra-flood');
  for (let i = 0; i < 50; i += 1) {
    engine.feed({
      type: 'ra',
      device: 'd',
      ts: 1_000,
      srcMac: 'aa:bb:cc:dd:ee:10',
      srcIp: 'fe80::1',
      prefixes: ['2001:db8::/64'],
      routerLifetime: 1800,
      count: 1,
    });
  }
  assert.equal(hits.length, 1);
});

test('replay: one BSSID answers five SSIDs', () => {
  const { engine, hits } = watch('karma-responder');
  for (let i = 0; i < 5; i += 1) {
    engine.feed({
      type: 'wifi',
      device: 'd',
      ts: 1_000,
      mac: 'aa:bb:cc:dd:ee:01',
      bssid: 'aa:bb:cc:dd:ee:f1',
      ssid: `net-${i}`,
      op: 'probe-resp',
    });
  }
  assert.equal(hits.length, 1);
});

test('replay: CNAME from a learned name to a tracker', () => {
  const { engine, hits } = watch('cname-cloak', { learnMs: 5_000 });
  engine.loadIndicators([
    { value: 'tracker.test', type: 'tracker', source: 'test', confidence: 1 },
  ]);
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'www.vendor.test',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
  });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 6_000,
    qname: 'www.vendor.test',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
    answers: [{ type: 'CNAME', value: 'ads.tracker.test', ttl: 60 }],
  });
  assert.equal(hits.length, 1);
});

test('replay: four JA4 strings to one server', () => {
  const { engine, hits } = watch('ja4-churn', { learnMs: 5_000 });
  engine.feed({
    type: 'tls',
    device: 'd',
    ts: 1_000,
    dstIp: '8.8.8.8',
    dstPort: 443,
    ja4: 'a',
    sni: 'a.vendor.com',
  });
  for (let i = 0; i < 4; i += 1) {
    engine.feed({
      type: 'tls',
      device: 'd',
      ts: 6_000,
      dstIp: '8.8.8.8',
      dstPort: 443,
      ja4: `b${i}`,
      sni: 'a.vendor.com',
    });
  }
  assert.equal(hits.length, 1);
});

test('replay: device wakes after a week and contacts a new family', () => {
  const { engine, hits } = watch('dormant-reactivation', { learnMs: 3 * DAY });
  for (let day = 0; day < 3; day += 1) {
    engine.feed({ ts: day * DAY, device: 'd', dst: 'known.example.com', bytes: 10 });
  }
  engine.feed({ ts: 10 * DAY, device: 'd', dst: 'fresh.example.net', bytes: 10 });
  assert.equal(hits.length, 1);
});

test('replay: one camera downloads a different firmware image', () => {
  const { engine, hits } = watch('firmware-size-divergence');
  for (const id of ['a', 'b', 'c']) {
    engine.feed({ ts: 1_000, device: id, dst: 'update.vendor.com', bytes: 10 });
  }
  engine.setPeerGroup('a', 'cams');
  engine.setPeerGroup('b', 'cams');
  engine.setPeerGroup('c', 'cams');
  engine.feed(
    flow({
      device: 'a',
      ts: 2_000,
      direction: 'in',
      bytesIn: 2_000_000,
      dstName: 'update.vendor.com',
    }),
  );
  engine.feed(
    flow({
      device: 'b',
      ts: 2_000,
      direction: 'in',
      bytesIn: 2_000_000,
      dstName: 'update.vendor.com',
    }),
  );
  engine.feed(
    flow({
      device: 'c',
      ts: 2_000,
      direction: 'in',
      bytesIn: 4_000_000,
      dstName: 'update.vendor.com',
    }),
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0].device, 'c');
});

test('replay: new STUN relay above 5 MB', () => {
  const { engine, hits } = watch('stun-turn-relay');
  engine.feed(flow({ dstPort: 3478, dstName: 'stun.example.com', bytesOut: 6_000_000 }));
  assert.equal(hits.length, 1);
});

test('replay: public source knocks then connects', () => {
  const { engine, hits } = watch('port-knock');
  for (const dstPort of [10, 20, 30]) {
    engine.feed(
      flow({ direction: 'in', srcIp: '8.8.8.8', dstPort, tcpOutcome: 'rejected', ts: 1_000 }),
    );
  }
  engine.feed(
    flow({
      direction: 'in',
      srcIp: '8.8.8.8',
      dstPort: 4444,
      tcpOutcome: 'established',
      ts: 2_000,
    }),
  );
  assert.equal(hits.length, 1);
});

test('replay: unlearned BACnet foreign-device registration', () => {
  const { engine, hits } = watch('bacnet-bbmd-write');
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'bacnet',
    role: 'server',
    peerIp: '192.0.2.8',
    op: 'Register-Foreign-Device',
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'critical');
});

test('replay: sixteen Modbus unit ids', () => {
  const { engine, hits } = watch('modbus-unit-sweep', { learnMs: 5_000 });
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'modbus',
    role: 'server',
    peerIp: '192.0.2.9',
    op: 'Read',
    unitId: 1,
  });
  for (let unit = 0; unit < 16; unit += 1) {
    engine.feed({
      type: 'app',
      device: 'd',
      ts: 6_000,
      proto: 'modbus',
      role: 'server',
      peerIp: '192.0.2.9',
      op: 'Read',
      unitId: unit,
    });
  }
  assert.equal(hits.length, 1);
});

test('replay: retained MQTT command from a new client', () => {
  const { engine, hits } = watch('mqtt-retained-command');
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'mqtt',
    role: 'client',
    peerIp: '192.0.2.10',
    op: 'PUBLISH',
    target: 'home/cmd/arm',
    flags: ['retain'],
  });
  assert.equal(hits.length, 1);
});

test('replay: RTSP client that never learned the stream', () => {
  const { engine, hits } = watch('rtsp-new-viewer');
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'rtsp',
    role: 'server',
    peerIp: '192.0.2.11',
    op: 'PLAY',
  });
  assert.equal(hits.length, 1);
});

test('replay: twenty allows in one hour', () => {
  const { engine, hits } = watch('suppression-abuse', { audit: true });
  engine.feed({ ts: 1_000, device: 'd', dst: 'a.example', bytes: 10 });
  for (let i = 0; i < 20; i += 1) engine.allow('d', 'dst', `h${i}.example`);
  engine.feed({ ts: 2_000, device: 'd', dst: 'b.example', bytes: 10 });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].device, '__engine__');
});
