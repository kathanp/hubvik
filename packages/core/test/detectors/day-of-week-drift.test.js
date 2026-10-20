'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');

const ID = 'day-of-week-drift';
const DAY = 86_400_000;

function box() {
  /** @type {Record<string, { enabled: boolean }>} */
  const off = {};
  for (const id of Object.keys(detectors)) if (id !== ID) off[id] = { enabled: false };
  return createEngine({
    shadow: true,
    learnMs: 7 * DAY,
    tiers: ['T0'],
    detectors: off,
  });
}

test('day-of-week-drift fires after two weeks and stays quiet before that', () => {
  const quiet = box();
  /** @type {any[]} */
  const early = [];
  quiet.on('shadow-anomaly', (row) => early.push(row));
  quiet.on('anomaly', () => assert.fail('shadow detector emitted anomaly'));
  quiet.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  quiet.flush(120_000);
  assert.strictEqual(early.length, 0);

  const engine = box();
  /** @type {any[]} */
  const found = [];
  engine.on('shadow-anomaly', (row) => found.push(row));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  engine.flush(120_000);
  const start = 14 * DAY;
  for (let i = 0; i < 8; i += 1) {
    engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: start + i * 60_000 });
  }
  engine.flush(start + 10 * 60_000);
  assert.ok(found.some((row) => row.detector === ID));
});

test('day-of-week-drift state round-trips and the cap stays small', () => {
  const engine = box();
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
  const saved = engine.exportBaseline({ createdAt: 1 });
  const next = box();
  next.importBaseline(saved);
  const again = next.exportBaseline({ createdAt: 1 });
  assert.deepStrictEqual(again.devices.d.detectors[ID].state, saved.devices.d.detectors[ID].state);
  const state = detectors[ID].createState();
  assert.ok(detectors[ID].memoryEstimate(state) <= 2048);
});
