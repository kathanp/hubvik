'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  isBogon,
  isPublic,
  isPrivateAnswer,
  isMulticast,
  isBroadcast,
  isLinkLocal,
  isLanUnicast,
} = require('../src/engine/net');

test('bogon checks cover IPv4, IPv6, and names that are not addresses', () => {
  assert.strictEqual(isBogon(''), false);
  assert.strictEqual(isBogon('not-an-ip'), false);
  assert.strictEqual(isBogon('10.0.0.1'), true);
  assert.strictEqual(isPublic('1.2.3.4'), true);
  assert.strictEqual(isPublic('10.0.0.1'), false);
  assert.strictEqual(isPublic('not-an-ip'), false);
  for (const ip of ['::', '::1', 'fe80::1', 'fc00::1', 'fd12::1', 'ff02::1', '2001:db8::1']) {
    assert.strictEqual(isBogon(ip), true, ip);
    assert.strictEqual(isPublic(ip), false, ip);
  }
  assert.strictEqual(isBogon('2001:4860:4860::8888'), false);
  assert.strictEqual(isPublic('2001:4860:4860::8888'), true);
  assert.strictEqual(isBogon('fe90::1'), true);
  assert.strictEqual(isLinkLocal('fe90::1'), true);
  assert.strictEqual(isPublic('fe90::1'), false);
  assert.strictEqual(isBogon('::ffff:10.1.2.3'), true);
  assert.strictEqual(isPublic('::ffff:10.1.2.3'), false);
  assert.strictEqual(isBogon('::ffff:8.8.8.8'), false);
  assert.strictEqual(isPublic('::ffff:8.8.8.8'), true);
  assert.strictEqual(isLinkLocal('::ffff:169.254.1.1'), true);
  assert.strictEqual(isMulticast('::ffff:224.0.0.1'), true);
  assert.strictEqual(isPrivateAnswer(1), false);
  assert.strictEqual(isPrivateAnswer('0.0.0.0'), true);
  assert.strictEqual(isPrivateAnswer('1.2.3.4'), false);
  assert.strictEqual(isMulticast('224.0.0.251'), true);
  assert.strictEqual(isMulticast('239.255.255.250'), true);
  assert.strictEqual(isMulticast('1.2.3.4'), false);
  assert.strictEqual(isMulticast('255.255.255.255'), false);
  assert.strictEqual(isBroadcast('255.255.255.255'), true);
  assert.strictEqual(isBroadcast('224.0.0.251'), false);
  assert.strictEqual(isMulticast('ff02::1'), true);
  assert.strictEqual(isLinkLocal('169.254.1.1'), true);
  assert.strictEqual(isLinkLocal('169.255.1.1'), false);
  assert.strictEqual(isLinkLocal('fe80::1'), true);
  assert.strictEqual(isLinkLocal('2001:4860:4860::8888'), false);
  assert.strictEqual(isLanUnicast('10.0.0.8'), true);
  assert.strictEqual(isLanUnicast('192.168.1.1'), true);
  assert.strictEqual(isLanUnicast('172.16.0.1'), true);
  assert.strictEqual(isLanUnicast('169.254.1.1'), true);
  assert.strictEqual(isLanUnicast('fd12::1'), true);
  assert.strictEqual(isLanUnicast('::ffff:10.1.2.3'), true);
  assert.strictEqual(isLanUnicast('203.0.113.1'), false);
  assert.strictEqual(isLanUnicast('100.64.0.1'), false);
  assert.strictEqual(isLanUnicast('127.0.0.1'), false);
  assert.strictEqual(isLanUnicast('1.2.3.4'), false);
  assert.strictEqual(isLanUnicast('224.0.0.251'), false);
});
