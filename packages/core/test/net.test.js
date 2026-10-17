'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { isBogon, isPublic, isPrivateAnswer } = require('../src/engine/net');

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
  assert.strictEqual(isPrivateAnswer(1), false);
  assert.strictEqual(isPrivateAnswer('0.0.0.0'), true);
  assert.strictEqual(isPrivateAnswer('1.2.3.4'), false);
});
