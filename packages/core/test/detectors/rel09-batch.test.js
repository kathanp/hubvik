'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');

/**
 * @param {string} id
 * @param {string[]} tiers
 */
function box(id, tiers) {
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const other of Object.keys(detectors)) if (other !== id) off[other] = { enabled: false };
  return createEngine({ shadow: true, learnMs: 0, tiers, detectors: off });
}

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1_000,
    srcIp: '192.0.2.10',
    srcPort: 40000,
    dstIp: '198.51.100.10',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 800,
    bytesIn: 800,
    pktsOut: 10,
    pktsIn: 10,
    durationMs: 30_000,
    ...extra,
  };
}

test('sni-ip-mismatch fires when the address was not in the answer set', () => {
  const engine = box('sni-ip-mismatch', ['T0', 'T2', 'T3']);
  /** @type {any[]} */
  const found = [];
  engine.on('anomaly', () => assert.fail('live'));
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'vendor.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.53',
    answers: [{ type: 'A', value: '198.51.100.8', ttl: 30 }],
  });
  engine.feed({
    type: 'tls',
    device: 'd',
    ts: 2_000,
    dstIp: '203.0.113.9',
    dstPort: 443,
    sni: 'vendor.example',
  });
  assert.strictEqual(found.length, 1);
  const saved = engine.exportBaseline({ createdAt: 1 });
  const next = box('sni-ip-mismatch', ['T0', 'T2', 'T3']);
  next.importBaseline(saved);
  assert.ok(next.exportBaseline({ createdAt: 1 }).devices.d.detectors['sni-ip-mismatch']);
});

test('reverse-shell-shape fires on a two-way small-packet session', () => {
  const engine = box('reverse-shell-shape', ['T0', 'T1']);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed(flow({}));
  engine.feed(flow({ pktsOut: 1, pktsIn: 1, dstIp: '198.51.100.11' }));
  assert.strictEqual(found.length, 1);
  assert.ok(
    detectors['reverse-shell-shape'].memoryEstimate({ known: new Set(), fired: new Map() }) <= 2048,
  );
});

test('mud-violation stays quiet without an ACL and fires outside it', () => {
  const engine = box('mud-violation', ['T0', 'T1', 'T2']);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed(flow({}));
  assert.strictEqual(found.length, 0);
  engine.loadMud('d', { allows: [{ dstPort: 443, proto: 'tcp', direction: 'out' }] });
  engine.feed(flow({ ts: 2_000, dstPort: 23 }));
  assert.strictEqual(found.length, 1);
});

test('dns-answer-mismatch needs the optional from field', () => {
  const engine = box('dns-answer-mismatch', ['T0', 'T2']);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  const base = {
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'vendor.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.53',
  };
  engine.feed(base);
  engine.feed({ ...base, ts: 2_000, from: '198.51.100.50' });
  assert.strictEqual(found.length, 1);
});

test('llmnr-nbns-poison fires on an unlearned name at port 5355', () => {
  const engine = box('llmnr-nbns-poison', ['T0', 'T2']);
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'camera.local',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.53',
    port: 5355,
    answers: [{ type: 'A', value: '192.0.2.10', ttl: 30 }],
  });
  assert.strictEqual(found.length, 1);
});
