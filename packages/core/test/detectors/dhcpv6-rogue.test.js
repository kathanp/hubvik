'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {string} serverIp
 */
function offer(ts, serverIp) {
  return {
    type: 'dhcp',
    device: 'd',
    ts,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'offer',
    v6: true,
    serverIp,
  };
}

test('dhcpv6-rogue fires on a second DHCPv6 server after the first is learned', () => {
  const eng = createEngine({ learnMs: 5000, tiers: ['T4'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'dhcpv6-rogue') hits.push(row);
  });
  eng.feed(offer(1000, '2001:db8::1'));
  eng.feed(offer(6000, '2001:db8::9'));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'critical');
});

test('dhcpv6-rogue ignores IPv4 DHCP and a configured server', () => {
  const eng = createEngine({ learnMs: 0, tiers: ['T4'], dhcpServers: ['2001:db8::1'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'dhcpv6-rogue') hits.push(row);
  });
  eng.feed({
    type: 'dhcp',
    device: 'd',
    ts: 1000,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'offer',
    serverIp: '10.0.0.1',
  });
  eng.feed(offer(2000, '2001:db8::1'));
  assert.deepEqual(hits, []);
});

test('dhcpv6-rogue keeps a single learned server across export and import', () => {
  const eng = createEngine({ learnMs: 5000, tiers: ['T4'] });
  eng.feed(offer(1000, '2001:db8::1'));
  const saved = eng.exportBaseline();
  const next = createEngine({ learnMs: 0, tiers: ['T4'] });
  next.importBaseline(saved);
  /** @type {any[]} */
  const hits = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'dhcpv6-rogue') hits.push(row);
  });
  next.feed(offer(1000, '2001:db8::1'));
  next.feed(offer(2000, '2001:db8::9'));
  assert.equal(hits.length, 1);
  assert.equal(
    next.exportBaseline().devices.d.detectors['dhcpv6-rogue'].state.server,
    '2001:db8::1',
  );
});
