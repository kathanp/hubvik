'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('ssdp notify and subscribe become events', () => {
  const parser = createParser({ now: () => 4, device: 'cam', srcIp: '192.0.2.10' });
  const notify = parser.write('NOTIFY * HTTP/1.1\nNT: urn:example\n');
  assert.strictEqual(notify[0].type, 'discovery');
  assert.strictEqual(notify[0].name, 'urn:example');
  const sub = parser.write('SUBSCRIBE / HTTP/1.1\nCALLBACK: <http://203.0.113.5:9/n>\n');
  assert.strictEqual(sub[0].op, 'SUBSCRIBE');
  assert.strictEqual(sub[0].target, '203.0.113.5');
  assert.deepStrictEqual(parser.write('GET / HTTP/1.1\n'), []);
});
