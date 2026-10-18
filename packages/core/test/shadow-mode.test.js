'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const dummy = {
  id: 'shadow-dummy',
  version: 1,
  requires: ['T0'],
  defaults: { severity: 'high' },
  meta: { mode: 'shadow', consumes: ['summary'] },
  createState() {
    return { n: 0 };
  },
  /**
   * @param {any} state
   * @param {any} ev
   */
  check(state, ev) {
    state.n += 1;
    return {
      severity: 'high',
      confidence: 1,
      ts: ev.ts,
      actual: 'shadow',
      expected: 'quiet',
      data: {},
    };
  },
  /**
   * @param {any} state
   */
  exportState(state) {
    return { n: state.n };
  },
  /**
   * @param {any} state
   * @param {any} saved
   */
  importState(state, saved) {
    state.n = saved.n;
  },
};

/**
 * @param {any} engine
 */
function drive(engine) {
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any[]} */
  const incidents = [];
  engine.on('anomaly', (row) => anomalies.push(row));
  engine.on('incident', (row) => incidents.push(row));
  engine.feed({ device: 'd', dst: 'known.example', bytes: 1, ts: 0 });
  engine.lock('d');
  engine.feed({ device: 'd', dst: 'evil.example', bytes: 1, ts: 120_000 });
  engine.flush(180_000);
  return { anomalies, incidents, baseline: engine.exportBaseline({ createdAt: 1 }) };
}

/**
 * @param {any} baseline
 */
function withoutDummy(baseline) {
  const copy = structuredClone(baseline);
  for (const device of Object.values(copy.devices)) {
    delete device.detectors['shadow-dummy'];
  }
  return copy;
}

/**
 * @param {number} ts
 * @param {number} port
 */
function scan(ts, port) {
  return {
    type: 'flow',
    device: 'd',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '198.51.100.9',
    dstPort: port,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 40,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 1,
  };
}

test('a shadow detector leaves the live stream and baseline unchanged', () => {
  const plain = drive(createEngine({ learnMs: 0 }));
  const withShadow = createEngine({ learnMs: 0 });
  withShadow.use(dummy);
  const noisy = drive(withShadow);
  assert.deepStrictEqual(noisy.anomalies, plain.anomalies);
  assert.deepStrictEqual(noisy.incidents, plain.incidents);
  assert.deepStrictEqual(withoutDummy(noisy.baseline), withoutDummy(plain.baseline));
  assert.ok(noisy.baseline.devices.d.detectors['shadow-dummy']);
});

test('shadow drafts do not feed alert-storm', () => {
  const engine = createEngine({ learnMs: 0 });
  engine.use(dummy);
  /** @type {string[]} */
  const names = [];
  engine.on('anomaly', (row) => names.push(row.detector));
  for (let i = 0; i < 1001; i++) engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: i });
  assert.ok(!names.includes('alert-storm'));
  assert.strictEqual(engine.stats().shadow['shadow-dummy'].fired, 1001);
  assert.strictEqual(engine.stats().shadow['shadow-dummy'].devices, 1);
});

test('canary counts are identical across two runs and stay out of the checkpoint', () => {
  /**
   * @returns {any}
   */
  function once() {
    const engine = createEngine({
      learnMs: 0,
      tiers: ['T0', 'T1'],
      windowMs: 1000,
      detectors: { 'vertical-scan': { canary: { minPorts: 1, factor: 1 } } },
    });
    for (let port = 1; port <= 3; port++) engine.feed(scan(port, port));
    engine.flush(2000);
    return engine;
  }
  const first = once();
  const second = once();
  assert.deepStrictEqual(first.stats().canary, second.stats().canary);
  assert.strictEqual(first.stats().canary['vertical-scan'].canaryOnly, 1);
  const saved = first.checkpoint({ createdAt: 1 });
  const restored = createEngine({
    learnMs: 0,
    tiers: ['T0', 'T1'],
    windowMs: 1000,
    detectors: { 'vertical-scan': { canary: { minPorts: 1, factor: 1 } } },
  });
  restored.restore(saved);
  for (let port = 1; port <= 3; port++) restored.feed(scan(10_000 + port, port));
  restored.flush(12_000);
  assert.strictEqual(restored.stats().canary['vertical-scan'].canaryOnly, 1);
});

test('a fifth canary is rejected and a promoted shadow detector warns once', () => {
  /** @type {Record<string, { canary: { minPorts: number } }>} */
  const detectors = {};
  for (const id of ['fan-out', 'volume-spike', 'new-port', 'new-destination', 'new-protocol']) {
    detectors[id] = { canary: { minPorts: 1 } };
  }
  assert.throws(() => createEngine({ detectors }), /at most 4 canaries/);

  const engine = createEngine({
    learnMs: 0,
    tiers: ['T0', 'T1'],
    detectors: { 'ttl-anomaly': { mode: 'live' } },
  });
  /** @type {string[]} */
  const codes = [];
  engine.on('warning', (warning) => {
    if (warning.code === 'SHADOW_PROMOTED_BY_HOST') codes.push(warning.code);
  });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 1 });
  assert.deepStrictEqual(codes, ['SHADOW_PROMOTED_BY_HOST']);
});
