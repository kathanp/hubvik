'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'cam',
    ts: 10_000,
    srcIp: '192.0.2.11',
    srcPort: 40000,
    dstIp: '203.0.113.5',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 40,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 20,
    ...extra,
  };
}

/**
 * @param {number} ts
 * @param {string} ip
 */
function ack(ts, ip) {
  return {
    type: 'dhcp',
    device: 'cam',
    ts,
    mac: 'aa:bb:cc:dd:ee:ff',
    msg: 'ack',
    requestedIp: ip,
  };
}

/**
 * @param {number} reorderMs
 */
function spoofCount(reorderMs) {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1'], reorderMs });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed(ack(0, '192.0.2.10'));
  engine.feed(flow({ ts: 10_000, srcIp: '192.0.2.11' }));
  engine.feed(ack(7_000, '192.0.2.11'));
  engine.flush();
  return anomalies.filter((item) => item.detector === 'src-spoof');
}

test('a DHCP ack 3s after the first flow is not src-spoof when the buffer is on', () => {
  assert.strictEqual(spoofCount(5_000).length, 0);
  assert.strictEqual(spoofCount(0).length, 1);
});

test('reorderMs 0 still delivers an event before flush', () => {
  const engine = createEngine({ learnMs: 0 });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  assert.ok(anomalies.some((item) => item.detector === 'new-destination'));
});

test('an event stays buffered until event time passes reorderMs', () => {
  const engine = createEngine({ learnMs: 0, reorderMs: 5_000 });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'new-destination'),
    [],
  );
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 5_000 });
  assert.deepStrictEqual(
    anomalies.filter((item) => item.detector === 'new-destination').map((item) => item.actual),
    ['a.example'],
  );
});

test('the reorder buffer overflows once per minute and restores', () => {
  const engine = createEngine({ learnMs: 0, reorderMs: 5_000, maxBuffered: 2 });
  /** @type {any[]} */
  const warnings = [];
  /** @type {any[]} */
  const anomalies = [];
  engine.on('warning', (warning) => warnings.push(warning));
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 1_000 });
  engine.feed({ device: 'd', dst: 'c.example', bytes: 10, ts: 2_000 });
  engine.feed({ device: 'd', dst: 'd.example', bytes: 10, ts: 3_000 });
  const overflows = () => warnings.filter((warning) => warning.code === 'REORDER_OVERFLOW');
  assert.strictEqual(overflows().length, 1);
  engine.feed({ device: 'd', dst: 'e.example', bytes: 10, ts: 61_000 });
  assert.strictEqual(overflows().length, 2);

  const saved = engine.checkpoint({ createdAt: 1 });
  const restored = createEngine({ learnMs: 0, reorderMs: 5_000, maxBuffered: 2 });
  /** @type {any[]} */
  const rest = [];
  restored.on('anomaly', (item) => rest.push(item));
  restored.restore(saved);
  restored.flush();
  const names = (list) =>
    list.filter((item) => item.detector === 'new-destination').map((item) => item.actual);
  const held = names(anomalies);
  engine.flush();
  assert.deepStrictEqual(held.concat(names(rest)), names(anomalies));
});
