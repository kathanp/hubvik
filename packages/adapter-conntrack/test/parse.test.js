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
  assert.strictEqual(event.direction, 'out');
  assert.strictEqual(event.bytesOut, 1200);
  assert.strictEqual(event.bytesIn, 9000);
  assert.strictEqual(event.tcpOutcome, 'established');
  assert.strictEqual(event.ts, 50);
});

test('an inbound line counts the device bytes and a silent handshake', () => {
  const parser = createParser({ now: () => 60 });
  const [event] = parser.write(
    'tcp      6 30 SYN_SENT src=8.8.8.8 dst=10.0.0.8 sport=9 dport=1111 packets=1 bytes=40 [UNREPLIED] src=10.0.0.8 dst=8.8.8.8 sport=1111 dport=9 packets=0 bytes=0',
  );
  assert.strictEqual(event.direction, 'in');
  assert.strictEqual(event.device, '10.0.0.8');
  assert.strictEqual(event.tcpOutcome, 'no-response');
  assert.strictEqual(event.bytesOut, 0);
  assert.strictEqual(event.bytesIn, 40);
});

test('an explicit direction function is not replaced', () => {
  const parser = createParser({
    now: () => 70,
    direction: () => 'out',
    device: (ip) => ip,
  });
  const [event] = parser.write(
    'tcp      6 30 SYN_SENT src=8.8.8.8 dst=10.0.0.8 sport=9 dport=1111 packets=1 bytes=40',
  );
  assert.strictEqual(event.direction, 'out');
  assert.strictEqual(event.device, '8.8.8.8');
  assert.strictEqual(event.bytesOut, 40);
});

test('a udp line has no tcp outcome', () => {
  const parser = createParser({ now: () => 80 });
  const [event] = parser.write(
    'udp      17 20 src=10.0.0.8 dst=8.8.8.8 sport=12345 dport=53 packets=1 bytes=60 src=8.8.8.8 dst=10.0.0.8 sport=53 dport=12345 packets=1 bytes=80',
  );
  assert.strictEqual(event.proto, 'udp');
  assert.strictEqual(event.tcpOutcome, undefined);
  assert.strictEqual(event.bytesOut, 60);
  assert.strictEqual(event.bytesIn, 80);
});

test('ignores unrelated text', () => {
  const parser = createParser();
  assert.deepStrictEqual(parser.write('conntrack v1.4.6 (conntrack-tools)'), []);
});
