'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('parses flow, dns, tls, http, and alert lines', () => {
  const parser = createParser({ device: () => 'cam-1', now: () => 1000 });
  const [flow] = parser.write(
    JSON.stringify({
      timestamp: '2026-01-05T00:00:00.000000+0000',
      event_type: 'flow',
      src_ip: '10.0.0.8',
      src_port: 40000,
      dest_ip: '1.2.3.4',
      dest_port: 443,
      proto: 'TCP',
      flow: { bytes_toserver: 100, bytes_toclient: 80 },
    }),
  );
  assert.strictEqual(flow.type, 'flow');
  assert.strictEqual(flow.bytesOut, 100);
  assert.strictEqual(flow.direction, 'out');

  const [dns] = parser.write(
    JSON.stringify({
      event_type: 'dns',
      src_ip: '10.0.0.8',
      dest_ip: '10.0.0.1',
      dns: {
        rrname: 'video.vendor.com',
        type: 'A',
        rcode: 'NOERROR',
        answers: [{ rdata: '1.2.3.4', rrtype: 'A' }],
      },
    }),
  );
  assert.strictEqual(dns.qname, 'video.vendor.com');

  const [tls] = parser.write(
    JSON.stringify({
      event_type: 'tls',
      src_ip: '10.0.0.8',
      dest_ip: '1.2.3.4',
      dest_port: 443,
      tls: { sni: 'video.vendor.com', ja4: 't13d', version: 'TLS 1.3', alpn: 'h2' },
    }),
  );
  assert.strictEqual(tls.sni, 'video.vendor.com');
  assert.deepStrictEqual(tls.alpn, ['h2']);

  const [http] = parser.write(
    JSON.stringify({
      event_type: 'http',
      src_ip: '10.0.0.8',
      dest_ip: '1.2.3.4',
      dest_port: 80,
      http: { http_method: 'GET', hostname: 'video.vendor.com', url: '/' },
    }),
  );
  assert.strictEqual(http.method, 'GET');
  assert.strictEqual(http.direction, 'out');

  const [alert] = parser.write(
    JSON.stringify({
      event_type: 'alert',
      src_ip: '10.0.0.8',
      dest_ip: '1.2.3.4',
      alert: { signature: 'ET SCAN', category: 'Attempted Information Leak', severity: 2 },
    }),
  );
  assert.strictEqual(alert.type, 'alert');
  assert.strictEqual(alert.signature, 'ET SCAN');
  assert.deepStrictEqual(parser.write('{'), []);
  assert.deepStrictEqual(parser.write(JSON.stringify({ event_type: 'stats' })), []);
});

test('http.direction is in when the device is dest_ip', () => {
  const parser = createParser({ now: () => 1000 });
  const [page] = parser.write(
    JSON.stringify({
      event_type: 'http',
      src_ip: '1.2.3.4',
      dest_ip: '10.0.0.8',
      dest_port: 80,
      http: { http_method: 'GET', url: '/GponForm/diag_Form' },
    }),
  );
  assert.strictEqual(page.direction, 'in');
  assert.strictEqual(page.device, '10.0.0.8');
});

test('flow_id, tcp outcome, inbound bytes, and dns ttl are kept', () => {
  const parser = createParser({ now: () => 1000 });
  const [inbound] = parser.write(
    JSON.stringify({
      event_type: 'flow',
      flow_id: 42,
      src_ip: '8.8.8.8',
      src_port: 9,
      dest_ip: '10.0.0.8',
      dest_port: 22,
      proto: 'TCP',
      flow: { bytes_toserver: 40, bytes_toclient: 7, state: 'new', pkts_toclient: 0 },
    }),
  );
  assert.strictEqual(inbound.direction, 'in');
  assert.strictEqual(inbound.device, '10.0.0.8');
  assert.strictEqual(inbound.bytesOut, 7);
  assert.strictEqual(inbound.bytesIn, 40);
  assert.strictEqual(inbound.tcpOutcome, 'no-response');
  assert.strictEqual(inbound.uid, '42');

  const [lane] = parser.write(
    JSON.stringify({
      event_type: 'flow',
      src_ip: '10.0.0.8',
      dest_ip: '10.0.0.9',
      dest_port: 80,
      proto: 'TCP',
      flow: { state: 'established', age: 1.5 },
      tcp: { rst: true },
    }),
  );
  assert.strictEqual(lane.direction, 'lan');
  assert.strictEqual(lane.tcpOutcome, 'reset');
  assert.strictEqual(lane.durationMs, 1500);

  const [query] = parser.write(
    JSON.stringify({
      event_type: 'dns',
      flow_id: 42,
      src_ip: '10.0.0.8',
      dest_ip: '10.0.0.1',
      dns: {
        rrname: 's3.amazonaws.com',
        type: 'A',
        rcode: 'NOERROR',
        answers: [{ rdata: '1.2.3.4', rrtype: 'A', ttl: 60 }],
      },
    }),
  );
  assert.strictEqual(query.uid, '42');
  assert.strictEqual(query.answers[0].ttl, 60);
});

test('a public source to a link-local or mapped private address is inbound', () => {
  const parser = createParser({ now: () => 1000 });
  const [link] = parser.write(
    JSON.stringify({
      event_type: 'flow',
      src_ip: '1.2.3.4',
      dest_ip: 'fe90::1',
      proto: 'TCP',
      flow: { bytes_toserver: 40, bytes_toclient: 0 },
    }),
  );
  assert.strictEqual(link.direction, 'in');
  assert.strictEqual(link.device, 'fe90::1');
  const [mapped] = parser.write(
    JSON.stringify({
      event_type: 'flow',
      src_ip: '8.8.8.8',
      dest_ip: '::ffff:10.0.0.8',
      proto: 'TCP',
      flow: { bytes_toserver: 40, bytes_toclient: 0 },
    }),
  );
  assert.strictEqual(mapped.direction, 'in');
  assert.strictEqual(mapped.device, '::ffff:10.0.0.8');
});
