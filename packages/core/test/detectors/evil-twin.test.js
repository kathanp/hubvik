'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {string} bssid
 */
function assoc(ts, bssid) {
  return {
    type: 'wifi',
    device: 'd',
    ts,
    mac: 'aa:bb:cc:dd:ee:01',
    bssid,
    ssid: 'home',
    op: 'assoc',
  };
}

test('evil-twin fires when a learned client joins an unlearned BSSID', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: ['T4'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'evil-twin') hits.push(row);
  });
  eng.feed(assoc(1000, 'aa:bb:cc:dd:ee:f0'));
  eng.feed(assoc(6000, 'aa:bb:cc:dd:ee:f9'));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'critical');
  assert.equal(hits[0].data.bssid, 'aa:bb:cc:dd:ee:f9');
});

test('evil-twin stays quiet for a BSSID the host listed', () => {
  const eng = createEngine({
    shadow: true,
    learnMs: 5000,
    tiers: ['T4'],
    ownBssids: ['aa:bb:cc:dd:ee:f9'],
  });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'evil-twin') hits.push(row);
  });
  eng.feed(assoc(1000, 'aa:bb:cc:dd:ee:f0'));
  eng.feed(assoc(6000, 'aa:bb:cc:dd:ee:f9'));
  assert.deepEqual(hits, []);
});

test('evil-twin import rejects more than 32 BSSIDs', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  eng.feed(assoc(1000, 'aa:bb:cc:dd:ee:f0'));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const bssids = [];
  for (let i = 0; i < 33; i += 1) {
    bssids.push(`aa:bb:cc:dd:ee:${i.toString(16).padStart(2, '0')}`);
  }
  assert.throws(
    () =>
      eng.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              'evil-twin': {
                v: 1,
                state: { ssids: [['home', bssids]], clients: [], fired: false },
              },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('evil-twin survives export and import', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: ['T4'] });
  eng.feed(assoc(1000, 'aa:bb:cc:dd:ee:f0'));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  next.importBaseline(saved);
  /** @type {any[]} */
  const hits = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'evil-twin') hits.push(row);
  });
  next.feed(assoc(2000, 'aa:bb:cc:dd:ee:f9'));
  assert.equal(hits.length, 1);
});
