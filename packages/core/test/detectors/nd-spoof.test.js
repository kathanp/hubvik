'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} ts
 * @param {string} ip
 * @param {string} mac
 * @param {boolean} [router]
 */
function na(ts, ip, mac, router) {
  return { type: 'nd', device: 'd', ts, op: 'na', ip, mac, router: router === true };
}

test('nd-spoof fires a router claim during learning and stays a shadow anomaly', () => {
  const eng = createEngine({ shadow: true, learnMs: 1e14, tiers: ['T4'], identity: 'auto' });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'nd-spoof') hits.push(row);
  });
  eng.on('anomaly', (row) => {
    if (row.detector === 'nd-spoof') hits.push({ live: true, ...row });
  });
  eng.feed(na(1000, '2001:db8::1', 'aa:bb:cc:dd:ee:01', true));
  eng.feed(na(2000, '2001:db8::1', 'aa:bb:cc:dd:ee:02', true));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].live, undefined);
  assert.equal(hits[0].severity, 'critical');
});

test('nd-spoof treats a new address for the same MAC as privacy rotation', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'], identity: 'auto' });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'nd-spoof') hits.push(row);
  });
  eng.feed({
    type: 'dhcp',
    device: 'aa:bb:cc:dd:ee:01',
    ts: 500,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'ack',
    v6: true,
    requestedIp: '2001:db8::10',
  });
  eng.feed(na(1000, '2001:db8::10', 'aa:bb:cc:dd:ee:01'));
  eng.feed(na(2000, '2001:db8::11', 'aa:bb:cc:dd:ee:01'));
  assert.deepEqual(hits, []);
});

test('nd-spoof other rebinds wait until watching', () => {
  const learning = createEngine({ shadow: true, learnMs: 1e14, tiers: ['T4'] });
  /** @type {any[]} */
  const early = [];
  learning.on('shadow-anomaly', (row) => {
    if (row.detector === 'nd-spoof') early.push(row);
  });
  learning.feed(na(1000, '2001:db8::20', 'aa:bb:cc:dd:ee:01'));
  learning.feed(na(2000, '2001:db8::20', 'aa:bb:cc:dd:ee:02'));
  assert.deepEqual(early, []);

  const eng = createEngine({ shadow: true, learnMs: 1000, tiers: ['T4'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'nd-spoof') hits.push(row);
  });
  eng.feed(na(1000, '2001:db8::20', 'aa:bb:cc:dd:ee:01'));
  eng.feed(na(3000, '2001:db8::20', 'aa:bb:cc:dd:ee:02'));
  assert.equal(hits.length, 1);
});

test('nd-spoof stops storing bindings at 5000', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  for (let i = 0; i < 5001; i += 1) {
    const hex = i.toString(16).padStart(4, '0');
    eng.feed(na(1000 + i, `2001:db8::${hex}`, 'aa:bb:cc:dd:ee:01'));
  }
  const bag = eng.scratch.get('nd-spoof');
  assert.equal(bag.bindings.size, 5000);
});

test('nd-spoof binding survives a checkpoint', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  eng.feed(na(1000, '2001:db8::30', 'aa:bb:cc:dd:ee:01'));
  const saved = eng.checkpoint();
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T4'] });
  next.restore(saved);
  /** @type {any[]} */
  const hits = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'nd-spoof') hits.push(row);
  });
  next.feed(na(2000, '2001:db8::30', 'aa:bb:cc:dd:ee:02'));
  assert.equal(hits.length, 1);
});
