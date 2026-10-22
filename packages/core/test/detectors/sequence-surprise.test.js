'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEngine } = require('../../src/index.js');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const MEDIUM = new Set(['medium', 'high', 'critical']);

/**
 * @param {number} ts
 * @param {number} dstPort
 */
function flow(ts, dstPort) {
  return {
    type: 'flow',
    device: 'cam',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40_000,
    dstIp: '8.8.8.8',
    dstPort,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 200,
    bytesIn: 200,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 20,
    dstName: 'update.vendor.com',
  };
}

test('a staged port-class order is silent for single detectors and fires sequence-surprise', () => {
  const eng = createEngine({
    shadow: true,
    sequence: true,
    learnMs: 20_000,
    windowMs: 1_000,
    tiers: TIERS,
  });
  /** @type {string[]} */
  const live = [];
  /** @type {any[]} */
  const sequence = [];
  eng.on('anomaly', (row) => {
    if (MEDIUM.has(row.severity)) live.push(row.detector);
  });
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'sequence-surprise') sequence.push(row);
  });
  for (let w = 0; w < 3; w += 1) {
    for (let i = 0; i < 21; i += 1) eng.feed(flow(w * 1_000 + i, 8443));
  }
  for (let w = 3; w < 12; w += 1) {
    for (let i = 0; i < 21; i += 1) eng.feed(flow(w * 1_000 + i, 443));
  }
  eng.lock('cam');
  for (let w = 0; w < 3; w += 1) {
    for (let i = 0; i < 21; i += 1) {
      eng.feed(flow(30_000 + w * 1_000 + i, i % 2 === 0 ? 443 : 8443));
    }
  }
  eng.flush();
  assert.deepEqual(live, []);
  assert.equal(sequence.length, 1);
  assert.equal(sequence[0].severity, 'medium');
});

test('sequence-surprise rejects a transition table over the cap', () => {
  const eng = createEngine({
    shadow: true,
    sequence: true,
    learnMs: 0,
    tiers: ['T0'],
  });
  eng.feed(flow(1_000, 443));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const counts = [];
  for (let i = 0; i < 129; i += 1) counts.push([`${i}|1`, 1]);
  assert.throws(
    () =>
      eng.importBaseline({
        ...saved,
        devices: {
          cam: {
            ...saved.devices.cam,
            detectors: {
              ...saved.devices.cam.detectors,
              'sequence-surprise': {
                v: 1,
                state: { known: [], counts, other: 0, prev: null, streak: 0 },
              },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});
