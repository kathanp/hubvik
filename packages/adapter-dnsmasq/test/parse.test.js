'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('joins a query and a reply', () => {
  const parser = createParser({ now: () => 9, device: () => 'cam-1', resolver: '10.0.0.1' });
  assert.deepStrictEqual(parser.write('dnsmasq[1]: query[A] video.vendor.com from 10.0.0.8'), []);
  const [event] = parser.write('dnsmasq[1]: reply video.vendor.com is 1.2.3.4');
  assert.strictEqual(event.qname, 'video.vendor.com');
  assert.strictEqual(event.rcode, 'NOERROR');
  assert.strictEqual(event.answers[0].value, '1.2.3.4');
  assert.strictEqual(event.device, 'cam-1');
});

test('maps NXDOMAIN', () => {
  const parser = createParser({ now: () => 1 });
  parser.write('query[A] missing.example from 10.0.0.8');
  const [event] = parser.write('reply missing.example is NXDOMAIN');
  assert.strictEqual(event.rcode, 'NXDOMAIN');
});
