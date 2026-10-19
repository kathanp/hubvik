'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { flow } = require('../../../../test/fixtures/flow');

/**
 * @param {number} ts
 * @param {number} durationMs
 * @param {string} [srcIp]
 */
function ssh(ts, durationMs, srcIp = '1.2.3.4') {
  return flow({
    ts,
    direction: 'in',
    srcIp,
    srcPort: 40000,
    dstIp: '10.0.0.5',
    dstPort: 22,
    durationMs,
  });
}

test('ssh-brute-then-session fires after ten short attempts and one long session', () => {
  const eng = createEngine({ learnMs: 0, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'ssh-brute-then-session') hits.push(row);
  });
  for (let i = 0; i < 10; i += 1) eng.feed(ssh(1000 + i, 200));
  eng.feed(ssh(2000, 60000));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'critical');
  assert.equal(hits[0].data.shorts, 10);
});

test('ssh-brute-then-session stays quiet when the long session is a different source', () => {
  const eng = createEngine({ learnMs: 0, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'ssh-brute-then-session') hits.push(row);
  });
  for (let i = 0; i < 10; i += 1) eng.feed(ssh(1000 + i, 200));
  eng.feed(ssh(2000, 60000, '9.9.9.9'));
  assert.deepEqual(hits, []);
});

test('ssh-brute-then-session import rejects more than 256 sources', () => {
  const eng = createEngine({ learnMs: 0, tiers: ['T1'] });
  eng.feed(ssh(1000, 200));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const sources = [];
  for (let i = 0; i < 257; i += 1) {
    sources.push([
      `203.0.113.${i % 200}`,
      { shorts: 1, firstShort: 1, lastShort: 1, fired: false },
    ]);
  }
  assert.throws(
    () =>
      eng.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: { 'ssh-brute-then-session': { v: 1, state: { sources } } },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('ssh-brute-then-session survives export and import', () => {
  const eng = createEngine({ learnMs: 0, tiers: ['T1'] });
  eng.feed(ssh(1000, 200));
  const saved = eng.exportBaseline();
  const next = createEngine({ learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  assert.equal(
    next.exportBaseline().devices.d.detectors['ssh-brute-then-session'].state.sources.length,
    1,
  );
});
