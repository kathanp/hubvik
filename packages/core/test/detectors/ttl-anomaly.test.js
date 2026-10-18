'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number | string} ttl
 * @param {number} ts
 * @param {string} [dstIp]
 */
function flow(ttl, ts, dstIp = '1.2.3.4') {
  return {
    type: 'flow',
    device: 'd',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp,
    dstPort: dstIp === '224.0.0.251' ? 5353 : dstIp === '239.255.255.250' ? 1900 : 443,
    proto: dstIp === '1.2.3.4' ? 'tcp' : 'udp',
    direction: 'out',
    bytesOut: 40,
    bytesIn: 40,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
    ttl,
  };
}

/**
 * @returns {any}
 */
function engine() {
  return createEngine({
    learnMs: 100_000,
    tiers: ['T1'],
    detectors: { 'ttl-anomaly': { enabled: true } },
  });
}

/**
 * @param {any} box
 * @param {number} ttl
 * @param {number} count
 */
function learn(box, ttl, count) {
  for (let i = 0; i < count; i++) box.feed(flow(ttl, i * 1_000));
  box.lock('d');
}

test('ttl-anomaly alerts on a new bucket after 20 samples and ignores the same bucket', () => {
  const changed = engine();
  /** @type {any[]} */
  const alerts = [];
  changed.on('shadow-anomaly', (row) => alerts.push(row));
  learn(changed, 64, 20);
  changed.feed(flow(128, 200_000));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'medium');
  assert.strictEqual(alerts[0].data.bucket, 128);
  assert.strictEqual(alerts[0].data.observedTtl, 128);
  assert.deepStrictEqual(alerts[0].data.learned, [64]);

  const same = engine();
  /** @type {any[]} */
  const quiet = [];
  same.on('shadow-anomaly', (row) => quiet.push(row));
  learn(same, 64, 20);
  same.feed(flow(63, 200_000));
  assert.deepStrictEqual(quiet, []);
});

test('ttl-anomaly ignores multicast TTLs and an unarmed device', () => {
  const box = engine();
  /** @type {any[]} */
  const alerts = [];
  box.on('shadow-anomaly', (row) => {
    if (row.detector === 'ttl-anomaly') alerts.push(row);
  });
  learn(box, 64, 20);
  box.feed(flow(2, 210_000, '239.255.255.250'));
  box.feed(flow(255, 220_000, '224.0.0.251'));
  assert.deepStrictEqual(alerts, []);

  const short = engine();
  short.on('shadow-anomaly', (row) => {
    if (row.detector === 'ttl-anomaly') alerts.push(row);
  });
  learn(short, 64, 19);
  short.feed(flow(128, 200_000));
  assert.deepStrictEqual(alerts, []);
});

test('ttl-anomaly drops an out-of-range TTL and restores learned buckets', () => {
  const box = engine();
  /** @type {string[]} */
  const warnings = [];
  box.on('warning', (warning) => warnings.push(warning.message));
  box.feed(flow(300, 0));
  assert.ok(warnings.some((message) => message.includes('flow.ttl')));

  const learned = engine();
  learn(learned, 64, 20);
  const saved = learned.exportBaseline({ createdAt: 1 });
  const next = engine();
  /** @type {any[]} */
  const alerts = [];
  next.on('shadow-anomaly', (row) => alerts.push(row));
  next.importBaseline(saved);
  next.feed(flow(64, 200_000));
  next.feed(flow(128, 201_000));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].data.bucket, 128);
});
