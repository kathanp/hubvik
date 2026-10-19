'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('iotwarden');
const { flow } = require('../fixtures/flow');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {string} id
 * @param {Record<string, unknown>} [extra]
 */
function watch(id, extra = {}) {
  const engine = createEngine({ learnMs: 0, tiers: TIERS, ...extra });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === id) hits.push(row);
  });
  return { engine, hits };
}

test('replay: exploit then a payload download', () => {
  const { engine, hits } = watch('exploit-then-download');
  engine.feed(
    flow({ ts: 1_000, direction: 'in', srcIp: '1.2.3.9', dstIp: '10.0.0.8', dstPort: 80 }),
  );
  engine.feed(
    flow({
      ts: 20_000,
      direction: 'out',
      dstIp: '9.9.9.9',
      dstName: 'loader.example',
      bytesIn: 180000,
    }),
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0].data.fetchHost, 'loader.example');
});

test('replay: ssh brute force then a session', () => {
  const { engine, hits } = watch('ssh-brute-then-session');
  for (let i = 0; i < 10; i += 1) {
    engine.feed(
      flow({
        ts: 1_000 + i * 1000,
        direction: 'in',
        srcIp: '198.51.100.20',
        dstIp: '10.0.0.8',
        dstPort: 22,
        durationMs: 400,
      }),
    );
  }
  engine.feed(
    flow({
      ts: 60_000,
      direction: 'in',
      srcIp: '198.51.100.20',
      dstIp: '10.0.0.8',
      dstPort: 22,
      durationMs: 90000,
    }),
  );
  assert.equal(hits.length, 1);
});

test('replay: cloud storage upload the device never used', () => {
  const { engine, hits } = watch('cloud-storage-exfil');
  engine.feed(
    flow({
      ts: 1_000,
      dstName: 'loot.r2.cloudflarestorage.com',
      bytesOut: 12 * 1024 * 1024,
    }),
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0].data.pattern, 'r2.cloudflarestorage.com');
});

test('replay: neighbor advertisement claims the router', () => {
  const { engine, hits } = watch('nd-spoof', { learnMs: 1e14 });
  engine.feed({
    type: 'nd',
    device: 'd',
    ts: 1000,
    op: 'na',
    ip: '2001:db8::1',
    mac: 'aa:bb:cc:dd:ee:01',
    router: true,
  });
  engine.feed({
    type: 'nd',
    device: 'd',
    ts: 2000,
    op: 'na',
    ip: '2001:db8::1',
    mac: 'aa:bb:cc:dd:ee:99',
    router: true,
  });
  assert.equal(hits.length, 1);
});

test('replay: rogue DHCPv6 server', () => {
  const { engine, hits } = watch('dhcpv6-rogue', { learnMs: 5000 });
  for (const [ts, serverIp] of [
    [1000, '2001:db8::1'],
    [6000, '2001:db8::99'],
  ]) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts,
      mac: 'aa:bb:cc:dd:ee:01',
      msg: 'offer',
      v6: true,
      serverIp,
    });
  }
  assert.equal(hits.length, 1);
});

test('replay: wifi deauthentication flood', () => {
  const { engine, hits } = watch('wifi-deauth-flood');
  for (let i = 0; i < 30; i += 1) {
    engine.feed({
      type: 'wifi',
      device: 'd',
      ts: 1000 + i,
      mac: 'aa:bb:cc:dd:ee:01',
      op: 'deauth',
    });
  }
  assert.equal(hits.length, 1);
});

test('replay: evil twin of a learned network', () => {
  const { engine, hits } = watch('evil-twin', { learnMs: 5000 });
  engine.feed({
    type: 'wifi',
    device: 'd',
    ts: 1000,
    mac: 'aa:bb:cc:dd:ee:01',
    bssid: 'aa:bb:cc:dd:ee:f0',
    ssid: 'home',
    op: 'assoc',
  });
  engine.feed({
    type: 'wifi',
    device: 'd',
    ts: 6000,
    mac: 'aa:bb:cc:dd:ee:01',
    bssid: 'aa:bb:cc:dd:ee:f9',
    ssid: 'home',
    op: 'assoc',
  });
  assert.equal(hits.length, 1);
});

test('replay: UPnP CallStranger callback', () => {
  const { engine, hits } = watch('upnp-callstranger');
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1000,
    proto: 'upnp',
    role: 'server',
    peerIp: '10.0.0.50',
    op: 'SUBSCRIBE',
    target: 'http://1.2.3.50/exfil',
  });
  assert.equal(hits.length, 1);
});

test('replay: new Matter controller', () => {
  const { engine, hits } = watch('matter-new-controller', { learnMs: 5000 });
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1000,
    proto: 'matter',
    role: 'server',
    peerIp: '10.0.0.2',
    op: 'AddNOC',
  });
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 6000,
    proto: 'matter',
    role: 'server',
    peerIp: '10.0.0.90',
    op: 'AddTrustedRootCertificate',
  });
  assert.equal(hits.length, 1);
});
