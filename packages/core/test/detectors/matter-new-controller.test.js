'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {string} peerIp
 * @param {string} [op]
 */
function matter(ts, peerIp, op = 'AddNOC') {
  return {
    type: 'app',
    device: 'd',
    ts,
    proto: 'matter',
    role: 'server',
    peerIp,
    op,
  };
}

test('matter-new-controller fires on AddNOC from an unlearned peer', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: ['T5'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'matter-new-controller') hits.push(row);
  });
  eng.feed(matter(1000, '10.0.0.2'));
  eng.feed(matter(6000, '10.0.0.9'));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
  assert.equal(hits[0].data.peer, '10.0.0.9');
});

test('matter-new-controller stays quiet for a controller learned at setup', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: ['T5'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'matter-new-controller') hits.push(row);
  });
  eng.feed(matter(1000, '10.0.0.2', 'AddTrustedRootCertificate'));
  eng.feed(matter(6000, '10.0.0.2', 'AddNOC'));
  assert.deepEqual(hits, []);
});

test('matter-new-controller import rejects a peer list over the destination cap', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'], maxDestinations: 4 });
  eng.feed(matter(1000, '10.0.0.2'));
  const saved = eng.exportBaseline({ createdAt: 1 });
  assert.throws(
    () =>
      eng.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              'matter-new-controller': {
                v: 1,
                state: { peers: ['a', 'b', 'c', 'd', 'e'], fired: false },
              },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('matter-new-controller survives export and import', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: ['T5'] });
  eng.feed(matter(1000, '10.0.0.2'));
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  next.importBaseline(eng.exportBaseline({ createdAt: 1 }));
  /** @type {any[]} */
  const hits = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'matter-new-controller') hits.push(row);
  });
  next.feed(matter(2000, '10.0.0.2'));
  next.feed(matter(3000, '10.0.0.9'));
  assert.equal(hits.length, 1);
});
