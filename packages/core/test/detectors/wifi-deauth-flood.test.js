'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {string} mac
 * @param {'deauth' | 'disassoc'} [op]
 */
function wifi(ts, mac, op = 'deauth') {
  return { type: 'wifi', device: 'd', ts, mac, op };
}

test('wifi-deauth-flood fires at 30 events in one window', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'wifi-deauth-flood') hits.push(row);
  });
  for (let i = 0; i < 30; i += 1) eng.feed(wifi(1000 + i, 'aa:bb:cc:dd:ee:01'));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
});

test('wifi-deauth-flood fires at 10 against one MAC', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'wifi-deauth-flood') hits.push(row);
  });
  for (let i = 0; i < 10; i += 1) eng.feed(wifi(1000 + i, 'aa:bb:cc:dd:ee:09', 'disassoc'));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].data.macCount, 10);
});

test('wifi-deauth-flood caps the per-MAC map at 5000', () => {
  const eng = createEngine({
    shadow: true,
    learnMs: 0,
    tiers: ['T4'],
    detectors: { 'wifi-deauth-flood': { minCount: 100000, perMac: 100000 } },
  });
  for (let i = 0; i < 5001; i += 1) {
    const mac = `02:00:00:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`;
    eng.feed(wifi(1000 + i, mac));
  }
  const bag = eng.scratch.get('wifi-deauth-flood');
  assert.ok(bag.byMac.size <= 5000);
});

test('wifi-deauth-flood counter survives a checkpoint', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  for (let i = 0; i < 9; i += 1) eng.feed(wifi(1000 + i, 'aa:bb:cc:dd:ee:01'));
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  next.restore(eng.checkpoint({ createdAt: 1 }));
  /** @type {any[]} */
  const hits = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'wifi-deauth-flood') hits.push(row);
  });
  next.feed(wifi(2000, 'aa:bb:cc:dd:ee:01'));
  assert.equal(hits.length, 1);
});
