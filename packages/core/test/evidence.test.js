'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../src/index.js');

const KEEP = new Set(['dns-rebinding', 'private-answer-for-public-name']);

/** @type {Record<string, { enabled: boolean }>} */
const ONLY_PRIVATE = {};
for (const det of Object.values(detectors)) {
  if (!KEEP.has(det.id)) ONLY_PRIVATE[det.id] = { enabled: false };
}

/**
 * @returns {object}
 */
function answer() {
  return {
    type: 'dns',
    device: 'd',
    ts: 0,
    qname: 'kim.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '0.0.0.0', ttl: 0 }],
  };
}

/**
 * @param {boolean} [evidence]
 */
function engine(evidence) {
  return createEngine({
    learnMs: 0,
    tiers: ['T0', 'T2'],
    detectors: ONLY_PRIVATE,
    evidence,
  });
}

test('a 0.0.0.0 answer keeps both anomalies and scores the fact once', () => {
  const first = engine();
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any[]} */
  const incidents = [];
  first.on('anomaly', (item) => anomalies.push(item));
  first.on('incident', (item) => incidents.push(item));
  const baseline = first.exportBaseline();
  first.feed(answer());
  assert.deepStrictEqual(anomalies.map((item) => item.detector).sort(), [
    'dns-rebinding',
    'private-answer-for-public-name',
  ]);
  assert.strictEqual(incidents.at(-1).anomalyIds.length, 2);
  assert.strictEqual(incidents.at(-1).score, 45);
  for (const item of anomalies) {
    assert.strictEqual(item.schema, 1);
    assert.strictEqual(item.dedupGroup, 'private-answer');
    assert.match(item.fingerprint, /^[0-9a-f]{16}$/);
    assert.strictEqual(item.evidence.events, 1);
    assert.strictEqual(item.evidence.sample.length, 1);
    assert.strictEqual(item.evidence.sample[0].qname, 'kim.example');
    assert.strictEqual(item.evidence.sample[0].tier, undefined);
    assert.ok(JSON.stringify(item.evidence.sample[0]).length <= 1024);
    assert.deepStrictEqual(item.evidence.window, { start: 0, end: 60_000 });
  }

  const second = engine();
  /** @type {any[]} */
  const again = [];
  second.on('anomaly', (item) => again.push(item));
  second.importBaseline(baseline);
  second.feed(answer());
  assert.deepStrictEqual(
    again.map((item) => item.fingerprint).sort(),
    anomalies.map((item) => item.fingerprint).sort(),
  );
});

test('evidence is omitted when the host turns it off', () => {
  const quiet = engine(false);
  /** @type {any[]} */
  const anomalies = [];
  quiet.on('anomaly', (item) => anomalies.push(item));
  quiet.feed(answer());
  assert.strictEqual(anomalies.length, 2);
  for (const item of anomalies) assert.strictEqual(item.evidence, undefined);
});
