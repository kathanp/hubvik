'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');
const contagion = require('../../src/detectors/graph-contagion.js');

/**
 * @returns {Record<string, { enabled: boolean }>}
 */
function onlyPair() {
  /** @type {Record<string, { enabled: boolean }>} */
  const options = {};
  for (const id of Object.keys(detectors)) {
    if (id !== 'new-destination' && id !== 'graph-contagion') options[id] = { enabled: false };
  }
  return options;
}

/**
 * @param {any} engine
 * @param {number} n
 */
function peers(engine, n) {
  engine.feed({
    type: 'dhcp',
    device: 'aa:bb:cc:dd:ee:10',
    ts: 1,
    mac: 'aa:bb:cc:dd:ee:10',
    msg: 'ack',
    requestedIp: '10.0.0.10',
  });
  for (let i = 0; i < n; i += 1) {
    engine.feed({
      type: 'flow',
      device: `peer-${i}`,
      ts: 1000 + i,
      srcIp: `10.1.0.${i + 1}`,
      srcPort: 40000,
      dstIp: '10.0.0.10',
      dstPort: 80,
      proto: 'tcp',
      direction: 'lan',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
    });
    engine.feed({
      device: `peer-${i}`,
      dst: `evil-${i}.example`,
      bytes: 80,
      ts: 20_000 + i,
    });
  }
}

test('replay: graph-contagion fires after four neighbors share a stage', () => {
  const engine = createEngine({
    shadow: true,
    learnMs: 10_000,
    tiers: ['T0', 'T1'],
    identity: 'auto',
    detectors: onlyPair(),
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'graph-contagion') hits.push(row);
  });
  peers(engine, 4);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].device, 'aa:bb:cc:dd:ee:10');
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.stage, 'c2');
  assert.strictEqual(hits[0].data.neighbors, 4);
  assert.strictEqual(hits[0].ts, 20_003);
});

test('graph-contagion stays quiet with two neighbors', () => {
  const engine = createEngine({
    shadow: true,
    learnMs: 10_000,
    tiers: ['T0', 'T1'],
    identity: 'auto',
    detectors: onlyPair(),
  });
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'graph-contagion') hits.push(row);
  });
  peers(engine, 2);
  assert.deepStrictEqual(hits, []);
});

test('graph-contagion keeps eight stages and rejects a ninth on import', () => {
  const dev = contagion.createState();
  for (let i = 0; i < 9; i += 1) {
    contagion.observe(dev, `stage-${i}`, 1000 + i, { severity: 'high' });
  }
  assert.strictEqual(dev.stages.size, 8);
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'], identity: 'auto' });
  engine.feed({
    type: 'dhcp',
    device: 'aa:bb:cc:dd:ee:10',
    ts: 1,
    mac: 'aa:bb:cc:dd:ee:10',
    msg: 'ack',
    requestedIp: '10.0.0.10',
  });
  peersLite(engine);
  const saved = engine.exportBaseline({ createdAt: 1 });
  const stages = [];
  for (let i = 0; i < 9; i += 1) stages.push([`s${i}`, { times: [1], fired: false }]);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        'aa:bb:cc:dd:ee:10': {
          ...saved.devices['aa:bb:cc:dd:ee:10'],
          detectors: { 'graph-contagion': { v: 1, state: { stages } } },
        },
      },
    });
  }, /exceeds cap/);
});

/**
 * Make sure the hub device exists so export has a row.
 * @param {any} engine
 */
function peersLite(engine) {
  engine.feed({ device: 'aa:bb:cc:dd:ee:10', dst: 'vendor.example', bytes: 10, ts: 50 });
}
