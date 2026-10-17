'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('parses an established conntrack line', () => {
  const parser = createParser({ now: () => 50, device: () => 'cam-1' });
  const [event] = parser.write(
    'tcp      6 100 ESTABLISHED src=10.0.0.8 dst=1.2.3.4 sport=51515 dport=443 packets=10 bytes=1200 src=1.2.3.4 dst=10.0.0.8 sport=443 dport=51515 packets=8 bytes=9000',
  );
  assert.strictEqual(event.device, 'cam-1');
  assert.strictEqual(event.dstIp, '1.2.3.4');
  assert.strictEqual(event.dstPort, 443);
  assert.strictEqual(event.bytesOut, 1200);
  assert.strictEqual(event.ts, 50);
});

test('ignores unrelated text', () => {
  const parser = createParser();
  assert.deepStrictEqual(parser.write('conntrack v1.4.6 (conntrack-tools)'), []);
});
