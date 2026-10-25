'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const NAME = 'edctgwib2n5l34t525zkxqzk5bqb6e5il2yiq5r6zu7gtlxa4uosn3qd.onion';

/**
 * @param {Record<string, unknown>} extra
 */
function dns(extra) {
  return {
    type: 'dns',
    device: 'cam',
    ts: 1000,
    qname: NAME,
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    ...extra,
  };
}

/**
 * @param {import('node:events').EventEmitter} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'onion-name') hits.push(row);
  });
  engine.on('anomaly', (row) => {
    if (row.detector === 'onion-name') hits.push(row);
  });
  return hits;
}

test('onion-name fires on a hidden-service name and stays quiet beside it', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2', 'T3'] });
  const hits = hitsOf(engine);
  engine.feed(dns({ qname: 'notonion.example' }));
  engine.feed(dns({ qname: 'hidden.onion.example' }));
  assert.strictEqual(hits.length, 0);
  engine.feed(dns({}));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.name, NAME);
  engine.feed(dns({ ts: 1000 + 86_399_999 }));
  assert.strictEqual(hits.length, 1);
  engine.feed(dns({ ts: 1000 + 86_400_000 }));
  assert.strictEqual(hits.length, 2);

  engine.feed({
    type: 'tls',
    device: 'cam',
    ts: 1000 + 86_400_000 + 1,
    dstIp: '9.9.9.9',
    dstPort: 443,
    sni: 'other.onion',
  });
  assert.strictEqual(hits.length, 3);
  engine.feed({
    type: 'flow',
    device: 'cam',
    ts: 1000 + 86_400_000 + 2,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '9.9.9.9',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 100,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
    dstName: 'third.onion',
  });
  assert.strictEqual(hits.length, 4);
});

test('onion-name is silent while learning and does not fire with shadow off', () => {
  const learning = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T2'] });
  const learningHits = hitsOf(learning);
  learning.feed(dns({}));
  assert.deepStrictEqual(learningHits, []);
  learning.lock('cam');
  learning.feed(dns({ ts: 90_000_000 }));
  assert.deepStrictEqual(learningHits, []);

  const off = createEngine({ shadow: false, learnMs: 0, tiers: ['T2'] });
  const offHits = hitsOf(off);
  off.feed(dns({}));
  assert.deepStrictEqual(offHits, []);
});

test('onion-name rejects an over-cap import and a forbidden key, and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  engine.feed(dns({}));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 65; i += 1) learned.push(`n${i}.onion`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'onion-name': { v: 1, state: { learned, seen: [] } } },
        },
      },
    });
  }, /exceeds cap/);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'onion-name': {
              v: 1,
              state: {
                ...saved.devices.cam.detectors['onion-name'].state,
                constructor: { no: true },
              },
            },
          },
        },
      },
    });
  }, /forbidden key/);

  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  next.feed(dns({ ts: 5000 }));
  assert.strictEqual(hits.length, 0);
  next.feed(dns({ ts: 1000 + 86_400_000, qname: 'fresh.onion' }));
  assert.strictEqual(hits.length, 1);
});

test('onion-name is silent on 14-day benign traffic for every device class', () => {
  for (const profile of CLASS_NAMES) {
    const events = simulate({
      profile,
      days: 14,
      seed: 1,
      startTs: T0,
      rich: true,
      discovery: true,
      ipv6: true,
    });
    const engine = createEngine({
      shadow: true,
      learnMs: 7 * DAY,
      tiers: TIERS,
      identity: 'auto',
    });
    engine.setDeviceClass(events[0].device, profile);
    const hits = hitsOf(engine);
    for (const event of events) engine.feed(event);
    engine.flush(T0 + 14 * DAY);
    assert.deepStrictEqual(
      hits.filter((row) => row.severity !== 'info' && row.severity !== 'low'),
      [],
      profile,
    );
  }
});
