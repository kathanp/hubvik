'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} n
 * @param {number} gap
 * @param {number} bytesOut
 * @param {number} [alt]
 */
function pulses(n, gap, bytesOut, alt) {
  /** @type {any[]} */
  const events = [];
  for (let i = 0; i < n; i += 1) {
    events.push({
      type: 'flow',
      device: 'cam',
      ts: i * gap,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: '9.9.9.9',
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: alt != null && i % 2 === 1 ? alt : bytesOut,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
    });
  }
  return events;
}

/**
 * @param {any} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'spectral-beacon') hits.push(row);
  });
  return hits;
}

test('replay: spectral-beacon fires when the period is real and the size is not stable', () => {
  const under = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const quiet = hitsOf(under);
  for (const event of pulses(24, 60_000, 100, 500)) under.feed(event);
  assert.deepStrictEqual(quiet, []);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (const event of pulses(25, 60_000, 100, 500)) engine.feed(event);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.ok(hits[0].data.autocorr >= 0.35);
});

test('spectral-beacon stays quiet when new-beacon would already fire', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  const hits = hitsOf(engine);
  for (const event of pulses(25, 60_000, 100)) engine.feed(event);
  assert.deepStrictEqual(hits, []);
});

test('spectral-beacon keeps 32 destinations and restores a track', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  for (let i = 0; i < 33; i += 1) {
    engine.feed({
      type: 'flow',
      device: 'cam',
      ts: i,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: `9.9.0.${i}`,
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 10,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 1,
    });
  }
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.strictEqual(saved.devices.cam.detectors['spectral-beacon'].state.tracks.length, 32);
  const tracks = [];
  for (let i = 0; i < 33; i += 1) {
    tracks.push([`8.8.0.${i}`, { gaps: [], sizes: [], last: 0, count: 1, first: 0, fired: false }]);
  }
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'spectral-beacon': { v: 1, state: { baseline: [], tracks } } },
        },
      },
    });
  }, /exceeds cap/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 2 });
  assert.strictEqual(again.devices.cam.detectors['spectral-beacon'].state.tracks.length, 32);
});
