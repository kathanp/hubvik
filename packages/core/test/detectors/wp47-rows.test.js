'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEngine } = require('../../src/index.js');

const DAY = 24 * 60 * 60 * 1000;

/**
 * @param {number} index
 * @param {number} ts
 */
function dns(index, ts) {
  return {
    type: 'dns',
    device: 'd',
    ts,
    qname: `n${index}.com`,
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
  };
}

test('lan-first-seen-domain keeps its daily cap across export and import', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'lan-first-seen-domain') hits.push(row);
  });
  for (let i = 0; i < 21; i += 1) eng.feed(dns(i, 1_000));
  assert.equal(hits.length, 20);
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  next.importBaseline(saved);
  /** @type {any[]} */
  const again = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'lan-first-seen-domain') again.push(row);
  });
  next.feed(dns(30, 1_000));
  assert.equal(again.length, 0);
  assert.throws(
    () =>
      next.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              ...saved.devices.d.detectors,
              'lan-first-seen-domain': { v: 1, state: { day: 0, count: 21 } },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('multivariate-outlier state survives export and import and rejects a streak over the cap', () => {
  const eng = createEngine({
    shadow: true,
    outlier: true,
    learnMs: 0,
    tiers: ['T0'],
  });
  eng.setDeviceClass('d', 'camera');
  eng.feed({ ts: 1_000, device: 'd', dst: 'a.example', bytes: 10 });
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = createEngine({
    shadow: true,
    outlier: true,
    learnMs: 0,
    tiers: ['T0'],
  });
  next.importBaseline(saved);
  const round = next.exportBaseline({ createdAt: 1 });
  assert.deepEqual(
    round.devices.d.detectors['multivariate-outlier'].state,
    saved.devices.d.detectors['multivariate-outlier'].state,
  );
  assert.throws(
    () =>
      next.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              ...saved.devices.d.detectors,
              'multivariate-outlier': { v: 1, state: { streak: 101 } },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('the daily cap resets on the next UTC day', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  /** @type {number} */
  let hits = 0;
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'lan-first-seen-domain') hits += 1;
  });
  for (let i = 0; i < 20; i += 1) eng.feed(dns(i, 1_000));
  eng.feed(dns(100, 1_000 + DAY));
  assert.equal(hits, 21);
});
