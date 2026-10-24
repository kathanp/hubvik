'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {Record<string, unknown>} extra
 */
function connect(extra) {
  return {
    type: 'app',
    device: 'hub',
    ts: 1000,
    proto: 'mqtt',
    role: 'server',
    peerIp: '10.0.0.70',
    op: 'CONNECT',
    target: 'plant/cmd/reboot',
    flags: ['will'],
    ...extra,
  };
}

/**
 * @param {any} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'mqtt-will-takeover') hits.push(row);
  });
  return hits;
}

test('replay: mqtt-will-takeover fires on a will to a command topic', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  const hits = hitsOf(engine);
  engine.feed(connect({}));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  engine.feed({
    type: 'app',
    device: 'hub',
    ts: 2000,
    proto: 'mqtt',
    role: 'client',
    peerIp: '10.0.0.71',
    op: 'PUBLISH',
    target: 'plant/cmd/reboot',
    flags: ['retain'],
  });
  assert.strictEqual(hits.length, 1);
});

test('mqtt-will-takeover stays quiet for a learned client and a topic without a command segment', () => {
  const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: ['T5'] });
  engine.feed(connect({ ts: 1000 }));
  const hits = hitsOf(engine);
  engine.feed(connect({ ts: 61_000 }));
  engine.feed(connect({ ts: 62_000, peerIp: '10.0.0.80', target: 'plant/status/temp' }));
  assert.deepStrictEqual(hits, []);
});

test('mqtt-will-takeover rejects 65 learned clients and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  engine.feed(connect({}));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 65; i += 1) learned.push(`10.0.0.${i}|plant/cmd`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        hub: {
          ...saved.devices.hub,
          detectors: { 'mqtt-will-takeover': { v: 1, state: { learned } } },
        },
      },
    });
  }, /exceeds cap/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  next.feed(connect({ ts: 5000, peerIp: '10.9.9.9' }));
  assert.strictEqual(hits.length, 1);
});
