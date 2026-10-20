'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('openwrt lines become dhcp, nd, and wifi events', () => {
  const parser = createParser({ now: () => 9 });
  const dhcp = parser.write('dnsmasq-dhcp: DHCPACK(br-lan) 192.0.2.10 aa:bb:cc:dd:ee:ff host');
  assert.strictEqual(dhcp[0].type, 'dhcp');
  assert.strictEqual(dhcp[0].requestedIp, '192.0.2.10');
  const v6 = parser.write('odhcpd: dhcpv6 reply aa:bb:cc:dd:ee:ff 00030001');
  assert.strictEqual(v6[0].v6, true);
  const nd = parser.write('odhcpd: ra from aa:bb:cc:dd:ee:ff fe80::1');
  assert.strictEqual(nd[0].type, 'nd');
  assert.strictEqual(nd[0].op, 'ra');
  const wifi = parser.write('hostapd: wlan0: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated');
  assert.strictEqual(wifi[0].op, 'assoc');
  assert.deepStrictEqual(parser.write('kernel: nothing'), []);
});
