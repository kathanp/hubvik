'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createParser } = require('../src/index.js');

test('parses a Zeek conn JSON line into a flow', () => {
  const parser = createParser({ log: 'conn', device: () => 'cam-1', now: (ts) => ts * 1000 });
  const [event] = parser.write(
    JSON.stringify({
      ts: 10,
      id: { orig_h: '10.0.0.8', orig_p: 40000, resp_h: '1.2.3.4', resp_p: 443 },
      proto: 'tcp',
      orig_bytes: 100,
      resp_bytes: 80,
      duration: 0.04,
    }),
  );
  assert.strictEqual(event.type, 'flow');
  assert.strictEqual(event.device, 'cam-1');
  assert.strictEqual(event.dstPort, 443);
  assert.strictEqual(event.durationMs, 40);
  assert.deepStrictEqual(parser.write('#separator'), []);
});

test('parses dns, ssl, http, and bacnet lines', () => {
  const dns = createParser({ log: 'dns', now: () => 5 });
  const [query] = dns.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '10.0.0.8', resp_h: '10.0.0.1' },
      query: 'video.vendor.com',
      qtype_name: 'A',
      rcode_name: 'NOERROR',
      answers: ['1.2.3.4'],
    }),
  );
  assert.strictEqual(query.qname, 'video.vendor.com');
  assert.strictEqual(query.answers[0].value, '1.2.3.4');

  const ssl = createParser({ log: 'ssl', now: () => 6 });
  const [handshake] = ssl.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '10.0.0.8', resp_h: '1.2.3.4', resp_p: 443 },
      server_name: 'video.vendor.com',
      ja4: 't13d',
      version: 'TLSv1.3',
      issuer: 'Vendor CA',
    }),
  );
  assert.strictEqual(handshake.type, 'tls');
  assert.strictEqual(handshake.cert.issuer, 'Vendor CA');

  const http = createParser({ log: 'http', now: () => 7 });
  const [page] = http.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '10.0.0.8', resp_h: '1.2.3.4', resp_p: 80 },
      method: 'GET',
      host: 'video.vendor.com',
      uri: '/',
    }),
  );
  assert.strictEqual(page.host, 'video.vendor.com');
  assert.strictEqual(page.direction, 'out');

  const bacnet = createParser({ log: 'bacnet', device: () => 'ahu-1', now: () => 8 });
  const [write] = bacnet.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '10.0.0.2', resp_h: '10.0.0.50' },
      service: 'WriteProperty',
    }),
  );
  assert.strictEqual(write.type, 'app');
  assert.strictEqual(write.proto, 'bacnet');
  assert.strictEqual(write.op, 'WriteProperty');
  assert.strictEqual(write.device, 'ahu-1');
});

test('http.direction is in when the device is id.resp_h', () => {
  const http = createParser({ log: 'http', now: () => 7 });
  const [page] = http.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '1.2.3.4', resp_h: '10.0.0.8', resp_p: 80 },
      method: 'GET',
      uri: '/GponForm/diag_Form',
    }),
  );
  assert.strictEqual(page.direction, 'in');
  assert.strictEqual(page.device, '10.0.0.8');
});

test('parses ICS and MQTT logs', () => {
  const id = { orig_h: '10.0.0.2', resp_h: '10.0.0.50' };
  const cases = [
    ['modbus', { func: 'read', address: '' }, 'modbus', 'read', undefined],
    ['dnp3', { fc_request: 'read' }, 'dnp3', 'read', undefined],
    ['s7comm', { rosctr: 'job' }, 's7', 'job', undefined],
    ['enip', {}, 'enip', 'read', undefined],
    ['mqtt_connect', {}, 'mqtt', 'CONNECT', undefined],
    ['mqtt_subscribe', { topics: ['floor/+/set'] }, 'mqtt', 'SUBSCRIBE', 'floor/+/set'],
    ['mqtt_publish', { topic: 'floor/1' }, 'mqtt', 'PUBLISH', 'floor/1'],
  ];
  for (const [log, extra, proto, op, target] of cases) {
    const parser = createParser({ log, now: () => 9 });
    const [event] = parser.write(JSON.stringify({ ts: 1, id, ...extra }));
    assert.strictEqual(event.proto, proto, log);
    assert.strictEqual(event.op, op, log);
    assert.strictEqual(event.target, target, log);
  }
});

test('conn carries outcome, direction, device bytes, and uid', () => {
  const parser = createParser({ log: 'conn', now: (ts) => ts * 1000 });
  const [inbound] = parser.write(
    JSON.stringify({
      ts: 10,
      uid: 'Cin',
      id: { orig_h: '8.8.8.8', orig_p: 9, resp_h: '10.0.0.8', resp_p: 22 },
      proto: 'tcp',
      conn_state: 'REJ',
      local_orig: false,
      local_resp: true,
      orig_bytes: 40,
      resp_bytes: 7,
      orig_pkts: 1,
      resp_pkts: 1,
    }),
  );
  assert.strictEqual(inbound.direction, 'in');
  assert.strictEqual(inbound.device, '10.0.0.8');
  assert.strictEqual(inbound.tcpOutcome, 'rejected');
  assert.strictEqual(inbound.bytesOut, 7);
  assert.strictEqual(inbound.bytesIn, 40);
  assert.strictEqual(inbound.uid, 'Cin');

  const [lan] = parser.write(
    JSON.stringify({
      ts: 11,
      id: { orig_h: '10.0.0.8', orig_p: 9, resp_h: '10.0.0.9', resp_p: 80 },
      proto: 'tcp',
      conn_state: 'S0',
      local_orig: true,
      local_resp: true,
      orig_bytes: 5,
      resp_bytes: 0,
    }),
  );
  assert.strictEqual(lan.direction, 'lan');
  assert.strictEqual(lan.tcpOutcome, 'no-response');
  assert.strictEqual(lan.bytesOut, 5);
});

test('dns answer type follows the query, and app logs keep unit and flags', () => {
  const dns = createParser({ log: 'dns', now: () => 1 });
  const [cname] = dns.write(
    JSON.stringify({
      ts: 1,
      uid: 'Cdns',
      id: { orig_h: '10.0.0.8', resp_h: '10.0.0.1' },
      query: 'alias.vendor.com',
      qtype_name: 'CNAME',
      rcode_name: 'NOERROR',
      answers: ['video.vendor.com'],
      TTLs: [30],
    }),
  );
  assert.strictEqual(cname.uid, 'Cdns');
  assert.strictEqual(cname.answers[0].type, 'CNAME');
  assert.strictEqual(cname.answers[0].ttl, 30);

  const modbus = createParser({ log: 'modbus', now: () => 2 });
  const [unit] = modbus.write(
    JSON.stringify({
      ts: 1,
      uid: 'Cmod',
      id: { orig_h: '10.0.0.2', resp_h: '10.0.0.50' },
      func: 'read',
      unit_id: 4,
    }),
  );
  assert.strictEqual(unit.unitId, 4);
  assert.strictEqual(unit.uid, 'Cmod');

  const publish = createParser({ log: 'mqtt_publish', now: () => 3 });
  const [retained] = publish.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '10.0.0.2', resp_h: '10.0.0.50' },
      topic: 'floor/1/cmd',
      retain: true,
    }),
  );
  assert.deepStrictEqual(retained.flags, ['retain']);

  const connect = createParser({ log: 'mqtt_connect', now: () => 4 });
  const [will] = connect.write(
    JSON.stringify({
      ts: 1,
      id: { orig_h: '10.0.0.2', resp_h: '10.0.0.50' },
      will_topic: 'floor/1/set',
    }),
  );
  assert.deepStrictEqual(will.flags, ['will']);
  assert.strictEqual(will.target, 'floor/1/set');
});

test('rejects an unknown log name and a broken line', () => {
  assert.throws(() => createParser({ log: 'weird' }), /zeek log is invalid/);
  const parser = createParser({ log: 'conn' });
  assert.deepStrictEqual(parser.write('not-json'), []);
  assert.deepStrictEqual(parser.write('{"id":{}}'), []);
});
