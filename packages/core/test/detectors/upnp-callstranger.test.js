'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {string} target
 */
function subscribe(target) {
  return {
    type: 'app',
    device: 'd',
    ts: 1000,
    proto: 'upnp',
    role: 'server',
    peerIp: '10.0.0.50',
    op: 'SUBSCRIBE',
    target,
  };
}

test('upnp-callstranger fires when the callback host is public', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'upnp-callstranger') hits.push(row);
  });
  eng.feed(subscribe('http://1.2.3.4/callback'));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'critical');
  assert.equal(hits[0].data.host, '1.2.3.4');
});

test('upnp-callstranger stays quiet for a private callback', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'upnp-callstranger') hits.push(row);
  });
  eng.feed(subscribe('http://10.0.0.9/callback'));
  eng.feed(subscribe('http://intranet/callback'));
  assert.deepEqual(hits, []);
});

test('upnp-callstranger survives export and import', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  eng.feed(subscribe('http://10.0.0.9/callback'));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  next.importBaseline(saved);
  /** @type {any[]} */
  const hits = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'upnp-callstranger') hits.push(row);
  });
  next.feed(subscribe('https://evil.example/cb'));
  assert.equal(hits.length, 1);
});
