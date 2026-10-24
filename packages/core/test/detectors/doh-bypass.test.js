'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {Record<string, unknown>} extra
 */
function tls(extra) {
  return {
    type: 'tls',
    device: 'cam',
    ts: 1000,
    dstIp: '1.1.1.1',
    dstPort: 443,
    sni: 'one.dns.google',
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
    if (row.detector === 'doh-bypass') hits.push(row);
  });
  return hits;
}

test('replay: doh-bypass fires on a public resolver over port 443', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  const hits = hitsOf(engine);
  engine.feed(tls({}));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.suffix, 'dns.google');
  engine.feed(tls({ ts: 2000 }));
  assert.strictEqual(hits.length, 1);
});

test('doh-bypass stays quiet on port 53 and on a learned suffix', () => {
  const quiet = createEngine({ shadow: true, learnMs: 0, tiers: ['T1', 'T3'] });
  const none = hitsOf(quiet);
  quiet.feed({
    type: 'flow',
    device: 'cam',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '8.8.8.8',
    dstPort: 53,
    proto: 'udp',
    direction: 'out',
    bytesOut: 60,
    bytesIn: 60,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
    dstName: 'dns.google',
  });
  assert.deepStrictEqual(none, []);

  const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: ['T3'] });
  engine.feed(tls({ ts: 1000 }));
  const hits = hitsOf(engine);
  engine.feed(tls({ ts: 61_000 }));
  engine.feed(tls({ ts: 62_000, sni: 'dns.quad9.net' }));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].data.suffix, 'dns.quad9.net');
});

test('doh-bypass rejects an over-cap learned list and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  engine.feed(tls({}));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 33; i += 1) learned.push(`dns${i}.example`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'doh-bypass': { v: 1, state: { learned, alerted: [] } } },
        },
      },
    });
  }, /exceeds cap/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T3'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  next.feed(tls({ ts: 90_000_000, sni: 'dns.cloudflare.com' }));
  assert.strictEqual(hits.length, 1);
});
