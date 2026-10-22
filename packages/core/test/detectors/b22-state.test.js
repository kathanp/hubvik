'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEngine } = require('../../src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {Record<string, unknown>} [opts]
 */
function make(opts = {}) {
  return createEngine({ shadow: true, learnMs: 0, tiers: TIERS, ...opts });
}

/**
 * @param {string} id
 * @param {(eng: ReturnType<typeof make>) => void} feed
 * @param {Record<string, unknown>} [opts]
 */
function roundTrip(id, feed, opts = {}) {
  const eng = make(opts);
  feed(eng);
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = make(opts);
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 1 });
  assert.deepEqual(again.devices.d.detectors[id], saved.devices.d.detectors[id]);
  return saved;
}

/**
 * @param {string} id
 * @param {Record<string, unknown>} state
 * @param {Record<string, unknown>} [opts]
 */
function reject(id, state, opts = {}) {
  const eng = make(opts);
  eng.feed({ ts: 1_000, device: 'd', dst: 'a.example', bytes: 10 });
  const saved = eng.exportBaseline({ createdAt: 1 });
  assert.throws(
    () =>
      make(opts).importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              ...saved.devices.d.detectors,
              [id]: { v: 1, state },
            },
          },
        },
      }),
    /exceeds cap/,
  );
}

test('dhcp-route-injection state round-trips and rejects 65 addresses', () => {
  roundTrip('dhcp-route-injection', (eng) => {
    eng.feed({
      type: 'flow',
      device: 'd',
      ts: 1_000,
      srcIp: '10.0.0.2',
      srcPort: 40_000,
      dstIp: '8.8.8.8',
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 100,
      bytesIn: 100,
      pktsOut: 1,
      pktsIn: 1,
      durationMs: 10,
    });
  });
  reject('dhcp-route-injection', { ips: Array.from({ length: 65 }, () => '8.8.8.8') });
});

test('wpad-hijack state round-trips and rejects 257 fired rows', () => {
  roundTrip('wpad-hijack', (eng) => {
    eng.feed({
      type: 'dns',
      device: 'd',
      ts: 1_000,
      qname: 'wpad.vendor.com',
      qtype: 'A',
      rcode: 'NXDOMAIN',
      resolver: '192.0.2.1',
    });
  });
  reject('wpad-hijack', {
    fired: Array.from({ length: 257 }, (_, i) => [`a${i}`, 1]),
  });
});

test('ra-flood keeps one anomaly when pairs pass the scratch cap', () => {
  const eng = make();
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'ra-flood') hits.push(row);
  });
  for (let i = 0; i < 5001; i += 1) {
    eng.feed({
      type: 'ra',
      device: 'd',
      ts: 1_000,
      srcMac: 'aa:bb:cc:dd:ee:10',
      srcIp: 'fe80::1',
      prefixes: [`2001:db8:${i.toString(16)}::/64`],
      routerLifetime: 1800,
      count: 1,
    });
  }
  assert.equal(hits.length, 1);
  roundTrip('ra-flood', (next) => {
    next.feed({
      type: 'ra',
      device: 'd',
      ts: 1_000,
      srcMac: 'aa:bb:cc:dd:ee:10',
      srcIp: 'fe80::1',
      prefixes: ['2001:db8::/64'],
      routerLifetime: 1800,
      count: 1,
    });
  });
});

test('karma-responder state round-trips and rejects 257 extra rows', () => {
  roundTrip('karma-responder', (eng) => {
    eng.feed({
      type: 'wifi',
      device: 'd',
      ts: 1_000,
      mac: 'aa:bb:cc:dd:ee:01',
      bssid: 'aa:bb:cc:dd:ee:f0',
      ssid: 'home',
      op: 'probe-resp',
    });
  });
  reject('karma-responder', { fired: false, extra: Array.from({ length: 257 }, (_, i) => i) });
});

test('cname-cloak state round-trips and rejects a family list over its cap', () => {
  roundTrip('cname-cloak', (eng) => {
    eng.feed({
      type: 'dns',
      device: 'd',
      ts: 1_000,
      qname: 'www.vendor.test',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '192.0.2.1',
    });
  });
  reject('cname-cloak', {
    families: Array.from({ length: 9 }, (_, i) => `f${i}.com`),
    fired: [],
    cap: 8,
  });
});

test('ja4-churn state round-trips and rejects a max over 10000', () => {
  roundTrip('ja4-churn', (eng) => {
    eng.feed({
      type: 'tls',
      device: 'd',
      ts: 1_000,
      dstIp: '8.8.8.8',
      dstPort: 443,
      sni: 'update.vendor.com',
      ja4: 't13d1516h2_8daaf6152771_b0da82dd1658',
    });
  });
  reject('ja4-churn', { max: 10001, fired: false });
});

test('dormant-reactivation state round-trips and rejects 65 days', () => {
  roundTrip('dormant-reactivation', (eng) => {
    eng.feed({ ts: 1_000, device: 'd', dst: 'known.example.com', bytes: 10 });
  });
  reject('dormant-reactivation', {
    days: Array.from({ length: 65 }, (_, i) => i),
    families: [],
    fired: false,
  });
});

test('firmware-size-divergence state round-trips and rejects 33 downloads', () => {
  roundTrip('firmware-size-divergence', (eng) => {
    eng.feed({
      type: 'flow',
      device: 'd',
      ts: 1_000,
      srcIp: '10.0.0.2',
      srcPort: 40_000,
      dstIp: '8.8.8.8',
      dstPort: 443,
      proto: 'tcp',
      direction: 'in',
      bytesOut: 100,
      bytesIn: 2_000_000,
      pktsOut: 1,
      pktsIn: 1,
      durationMs: 10,
      dstName: 'update.vendor.com',
    });
  });
  reject('firmware-size-divergence', {
    downloads: Array.from({ length: 33 }, () => ({
      ts: 1,
      family: 'vendor.com',
      bytes: 2_000_000,
    })),
    fired: false,
  });
});

test('stun-turn-relay state round-trips and rejects 65 hosts', () => {
  roundTrip('stun-turn-relay', (eng) => {
    eng.feed({
      type: 'flow',
      device: 'd',
      ts: 1_000,
      srcIp: '10.0.0.2',
      srcPort: 40_000,
      dstIp: '8.8.8.8',
      dstPort: 3478,
      proto: 'udp',
      direction: 'out',
      bytesOut: 100,
      bytesIn: 100,
      pktsOut: 1,
      pktsIn: 1,
      durationMs: 10,
      dstName: 'stun.example.com',
    });
  });
  reject('stun-turn-relay', {
    hosts: Array.from({ length: 65 }, (_, i) => `h${i}.com`),
    fired: false,
  });
});

test('port-knock state round-trips and rejects 257 sources', () => {
  roundTrip('port-knock', (eng) => {
    eng.feed({
      type: 'flow',
      device: 'd',
      ts: 1_000,
      srcIp: '8.8.8.8',
      srcPort: 40_000,
      dstIp: '10.0.0.2',
      dstPort: 10,
      proto: 'tcp',
      direction: 'in',
      bytesOut: 100,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
      tcpOutcome: 'rejected',
    });
  });
  reject('port-knock', { seen: Array.from({ length: 257 }, (_, i) => `203.0.113.${i % 200}`) });
});

test('bacnet-bbmd-write state round-trips and rejects 65 clients', () => {
  roundTrip('bacnet-bbmd-write', (eng) => {
    eng.feed({
      type: 'app',
      device: 'd',
      ts: 1_000,
      proto: 'bacnet',
      role: 'server',
      peerIp: '192.0.2.8',
      op: 'Read',
    });
  });
  reject('bacnet-bbmd-write', { clients: Array.from({ length: 65 }, (_, i) => `192.0.2.${i}`) });
});

test('modbus-unit-sweep state round-trips and rejects a max over 256', () => {
  roundTrip('modbus-unit-sweep', (eng) => {
    eng.feed({
      type: 'app',
      device: 'd',
      ts: 1_000,
      proto: 'modbus',
      role: 'server',
      peerIp: '192.0.2.9',
      op: 'Read',
      unitId: 1,
    });
  });
  reject('modbus-unit-sweep', { max: 257, fired: false });
});

test('mqtt-retained-command state round-trips and rejects 129 learned keys', () => {
  roundTrip('mqtt-retained-command', (eng) => {
    eng.feed({
      type: 'app',
      device: 'd',
      ts: 1_000,
      proto: 'mqtt',
      role: 'client',
      peerIp: '192.0.2.10',
      op: 'PUBLISH',
      target: 'home/status/temp',
      flags: [],
    });
  });
  reject('mqtt-retained-command', {
    learned: Array.from({ length: 129 }, (_, i) => `192.0.2.10|home/cmd/${i}`),
  });
});

test('rtsp-new-viewer state round-trips and rejects 65 clients', () => {
  roundTrip('rtsp-new-viewer', (eng) => {
    eng.feed({
      type: 'app',
      device: 'd',
      ts: 1_000,
      proto: 'rtsp',
      role: 'server',
      peerIp: '192.0.2.11',
      op: 'OPTIONS',
    });
  });
  reject('rtsp-new-viewer', {
    clients: Array.from({ length: 65 }, (_, i) => `192.0.2.${i}`),
    fired: [],
  });
});

test('suppression-abuse state round-trips and rejects 21 extra rows', () => {
  roundTrip(
    'suppression-abuse',
    (eng) => {
      eng.feed({ ts: 1_000, device: 'd', dst: 'a.example', bytes: 10 });
    },
    { audit: true },
  );
  reject('suppression-abuse', { fired: false, extra: Array.from({ length: 21 }, (_, i) => i) });
});
