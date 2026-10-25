'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const LIFE = 172800000;

/**
 * @param {Record<string, unknown>} extra
 */
function tls(extra) {
  return {
    type: 'tls',
    device: 'cam',
    ts: 1000,
    dstIp: '9.9.9.9',
    dstPort: 443,
    sni: 'c2.example',
    cert: {
      sha256: 'abc123',
      notBefore: 0,
      notAfter: LIFE,
    },
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
    if (row.detector === 'short-lived-cert') hits.push(row);
  });
  return hits;
}

test('short-lived-cert fires at a 48 hour lifetime and stays quiet one millisecond over', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const hits = hitsOf(engine);
  engine.feed(tls({}));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'medium');
  assert.strictEqual(hits[0].data.lifetimeMs, LIFE);
  engine.feed(tls({ ts: 2000 }));
  assert.strictEqual(hits.length, 1);

  const over = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const overHits = hitsOf(over);
  over.feed(tls({ cert: { sha256: 'abc123', notBefore: 0, notAfter: LIFE + 1 } }));
  assert.deepStrictEqual(overHits, []);
});

test('short-lived-cert ignores a missing notBefore, a reversed span, and a learned name', () => {
  const missing = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const missingHits = hitsOf(missing);
  missing.feed(tls({ cert: { sha256: 'abc123', notAfter: LIFE, notBefore: 'soon' } }));
  missing.feed(tls({ cert: { sha256: 'abc123', notBefore: 10, notAfter: 10 } }));
  assert.deepStrictEqual(missingHits, []);

  const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: ['T3'] });
  engine.feed(tls({ ts: 1000, cert: { sha256: 'vendor', notBefore: 0, notAfter: 400 * DAY } }));
  const hits = hitsOf(engine);
  engine.feed(tls({ ts: 120_000 }));
  assert.strictEqual(hits.length, 0);
  engine.feed(
    tls({
      ts: 130_000,
      sni: 'other.example',
      cert: { sha256: 'new', notBefore: 0, notAfter: LIFE },
    }),
  );
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].data.name, 'other.example');
});

test('short-lived-cert fires again at 86400000 ms and not one millisecond earlier', () => {
  const quiet = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const quietHits = hitsOf(quiet);
  quiet.feed(tls({ ts: 1000 }));
  quiet.feed(
    tls({ ts: 1000 + 86_400_000 - 1, cert: { sha256: 'abc123', notBefore: 0, notAfter: LIFE } }),
  );
  assert.strictEqual(quietHits.length, 1);

  const again = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const hits = hitsOf(again);
  again.feed(tls({ ts: 1000 }));
  again.feed(tls({ ts: 1000 + 86_400_000 }));
  assert.strictEqual(hits.length, 2);
});

test('short-lived-cert is silent while learning, rejects an over-cap list, and restores', () => {
  const learning = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T3'] });
  const learningHits = hitsOf(learning);
  learning.feed(tls({}));
  assert.deepStrictEqual(learningHits, []);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  engine.feed(tls({}));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 65; i += 1) learned.push(`name${i}.example`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'short-lived-cert': { v: 1, state: { learned, seen: [] } } },
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
            'short-lived-cert': {
              v: 1,
              state: {
                ...saved.devices.cam.detectors['short-lived-cert'].state,
                constructor: { no: true },
              },
            },
          },
        },
      },
    });
  }, /forbidden key/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  next.feed(tls({ ts: 5000 }));
  assert.strictEqual(hits.length, 0);
  next.feed(
    tls({
      ts: 1000 + 86_400_000,
      sni: 'fresh.example',
      cert: { sha256: 'fresh', notBefore: 0, notAfter: LIFE },
    }),
  );
  assert.strictEqual(hits.length, 1);
});

test('short-lived-cert is silent on 14-day benign traffic for every device class', () => {
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
