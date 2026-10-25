'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const LABEL = 'a'.repeat(20);

/**
 * @param {Record<string, unknown>} extra
 */
function dns(extra) {
  return {
    type: 'dns',
    device: 'cam',
    ts: 1000,
    qname: `${LABEL}.example`,
    qtype: 'TXT',
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
    if (row.detector === 'txt-channel') hits.push(row);
  });
  return hits;
}

test('txt-channel fires on the 12th short TXT query and stays quiet under that', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  const hits = hitsOf(engine);
  for (let i = 0; i < 11; i += 1) engine.feed(dns({ ts: 1000 + i }));
  assert.strictEqual(hits.length, 0);
  engine.feed(dns({ ts: 1012 }));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.queries, 12);
  engine.feed(dns({ ts: 1013 }));
  assert.strictEqual(hits.length, 1);
});

test('txt-channel ignores A records, a 19-character label, and a 41-character label', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  const hits = hitsOf(engine);
  for (let i = 0; i < 12; i += 1) engine.feed(dns({ ts: 1000 + i, qtype: 'A' }));
  for (let i = 0; i < 12; i += 1) {
    engine.feed(dns({ ts: 2000 + i, qname: `${'b'.repeat(19)}.example` }));
  }
  for (let i = 0; i < 12; i += 1) {
    engine.feed(dns({ ts: 3000 + i, qname: `${'c'.repeat(41)}.example` }));
  }
  assert.deepStrictEqual(hits, []);
  for (let i = 0; i < 12; i += 1) {
    engine.feed(dns({ ts: 4000 + i, qtype: 'NULL', qname: `${'d'.repeat(40)}.example` }));
  }
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].data.qtype, 'NULL');
});

test('txt-channel is silent while learning and on a learned name', () => {
  const learning = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T2'] });
  const learningHits = hitsOf(learning);
  for (let i = 0; i < 12; i += 1) learning.feed(dns({ ts: 1000 + i }));
  assert.deepStrictEqual(learningHits, []);

  const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: ['T2'] });
  for (let i = 0; i < 12; i += 1) engine.feed(dns({ ts: 1000 + i }));
  const hits = hitsOf(engine);
  for (let i = 0; i < 12; i += 1) engine.feed(dns({ ts: 120_000 + i }));
  assert.strictEqual(hits.length, 0);
  for (let i = 0; i < 12; i += 1) {
    engine.feed(dns({ ts: 130_000 + i, qname: `${'e'.repeat(20)}.example` }));
  }
  assert.strictEqual(hits.length, 1);
});

test('txt-channel rejects an over-cap name list and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  for (let i = 0; i < 11; i += 1) engine.feed(dns({ ts: 1000 + i }));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 65; i += 1) learned.push(`name${i}.example`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: {
            'txt-channel': { v: 1, state: { learned, win: 0, counts: [], fired: [] } },
          },
        },
      },
    });
  }, /exceeds cap/);
  const bad = { learned: [], win: 0, counts: [], fired: [], constructor: { no: true } };
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'txt-channel': { v: 1, state: bad } },
        },
      },
    });
  }, /forbidden key/);

  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  next.feed(dns({ ts: 5000 }));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].data.queries, 12);
});

test('txt-channel stops counting names past 64 in one window', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  const hits = hitsOf(engine);
  for (let n = 0; n < 64; n += 1) {
    engine.feed(dns({ ts: 1000 + n, qname: `${'f'.repeat(20)}${n}.example` }));
  }
  for (let i = 0; i < 12; i += 1) {
    engine.feed(dns({ ts: 2000 + i, qname: `${'g'.repeat(20)}.example` }));
  }
  assert.deepStrictEqual(hits, []);
});

test('txt-channel is silent on 14-day benign traffic for every device class', () => {
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
