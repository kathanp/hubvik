'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {number} n
 * @param {number} ts
 */
function reads(n, ts) {
  /** @type {any[]} */
  const events = [];
  for (let i = 0; i < n; i += 1) {
    events.push({
      type: 'app',
      device: 'plc',
      ts: ts + i,
      proto: 'modbus',
      role: 'server',
      peerIp: '10.0.0.40',
      op: 'ReadHoldingRegisters',
      target: `hr-${i}`,
    });
  }
  return events;
}

/**
 * @param {any} engine
 */
function hitsOf(engine) {
  /** @type {any[]} */
  const hits = [];
  engine.on('shadow-anomaly', (row) => {
    if (row.detector === 'modbus-address-sweep') hits.push(row);
  });
  return hits;
}

test('replay: modbus-address-sweep fires at 24 addresses and stays quiet at 23', () => {
  const under = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  const quiet = hitsOf(under);
  for (const event of reads(23, 1000)) under.feed(event);
  assert.deepStrictEqual(quiet, []);

  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  const hits = hitsOf(engine);
  for (const event of reads(24, 1000)) engine.feed(event);
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].severity, 'high');
  assert.strictEqual(hits[0].data.targets, 24);

  const units = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  const unitHits = hitsOf(units);
  for (let unit = 0; unit < 24; unit += 1) {
    units.feed({
      type: 'app',
      device: 'plc',
      ts: 1000 + unit,
      proto: 'modbus',
      role: 'server',
      peerIp: '10.0.0.41',
      op: 'ReadHoldingRegisters',
      target: 'hr-0',
      unitId: unit,
    });
  }
  assert.deepStrictEqual(unitHits, []);
});

test('modbus-address-sweep stays quiet when learning already saw more than 4 addresses', () => {
  const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: ['T5'] });
  for (const event of reads(5, 1000)) engine.feed(event);
  const hits = hitsOf(engine);
  for (const event of reads(24, 61_000)) engine.feed(event);
  assert.deepStrictEqual(hits, []);
});

test('modbus-address-sweep rejects a learned max over 256 and restores', () => {
  const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  engine.feed(reads(1, 1000)[0]);
  const saved = engine.exportBaseline({ createdAt: 1 });
  assert.throws(() => {
    engine.importBaseline({
      ...saved,
      devices: {
        plc: {
          ...saved.devices.plc,
          detectors: { 'modbus-address-sweep': { v: 1, state: { max: 257, fired: false } } },
        },
      },
    });
  }, /exceeds cap/);
  const next = createEngine({ shadow: true, learnMs: 0, tiers: ['T5'] });
  next.importBaseline(saved);
  const hits = hitsOf(next);
  for (const event of reads(24, 2000)) next.feed(event);
  assert.strictEqual(hits.length, 1);
});
