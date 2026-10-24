'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

const NAMES = [
  'homepage',
  'clickdown',
  'software',
  'wordlist',
  'newsroom',
  'playbook',
  'backdoor',
  'cloudsync',
];

/**
 * @param {string} label
 * @param {number} ts
 * @param {Record<string, unknown>} [extra]
 */
function dns(label, ts, extra) {
  return {
    type: 'dns',
    device: 'cam',
    ts,
    qname: `${label}.evil.test`,
    qtype: 'A',
    rcode: 'NXDOMAIN',
    resolver: '1.1.1.1',
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
    if (row.detector === 'dictionary-dga') hits.push(row);
  });
  return hits;
}

test('replay: dictionary-dga fires on eight joined names and stays quiet at seven', () => {
  const under = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  const quiet = hitsOf(under);
  NAMES.slice(0, 7).forEach((label, i) => under.feed(dns(label, 1000 + i)));
  assert.deepStrictEqual(quiet, []);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  const hits = hitsOf(engine);
  NAMES.forEach((label, i) => engine.feed(dns(label, 1000 + i)));
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'medium');
  assert.strictEqual(hits[0].data.names, 8);
});

test('dictionary-dga stays quiet for a learned family and a normal answer', () => {
  const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: ['T2'] });
  engine.feed(
    dns('homepage', 1000, {
      rcode: 'NOERROR',
      answers: [{ type: 'A', value: '1.2.3.4', ttl: 3600 }],
    }),
  );
  const hits = hitsOf(engine);
  NAMES.forEach((label, i) => engine.feed(dns(label, 61_000 + i)));
  engine.feed(
    dns('videovendor', 70_000, {
      qname: 'videovendor.other.test',
      rcode: 'NOERROR',
      answers: [{ type: 'A', value: '1.2.3.4', ttl: 3600 }],
    }),
  );
  assert.deepStrictEqual(hits, []);
});

test('dictionary-dga rejects 257 learned families and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  engine.feed(dns('homepage', 1000));
  const saved = engine.exportBaseline({ createdAt: 1 });
  const learned = [];
  for (let i = 0; i < 257; i += 1) learned.push(`w${i}.test`);
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        cam: {
          ...saved.devices.cam,
          detectors: { 'dictionary-dga': { v: 1, state: { learned } } },
        },
      },
    });
  }, /exceeds cap/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T2'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  NAMES.forEach((label, i) => next.feed(dns(label, 2000 + i, { qname: `${label}.other.test` })));
  assert.strictEqual(hits.length, 1);
});
