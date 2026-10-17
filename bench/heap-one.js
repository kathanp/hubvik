'use strict';

const { createEngine, detectors } = require('../packages/core/src/index.js');
const { simulate } = require('../test/fixtures/sim');
const { CLASS_NAMES } = require('../test/fixtures/profiles');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * Heap after two forced collections.
 * @returns {number}
 */
function heapUsed() {
  if (typeof global.gc !== 'function') throw new Error('heap profile needs node --expose-gc');
  global.gc();
  global.gc();
  return process.memoryUsage().heapUsed;
}

/**
 * One 7-day rich measurement. DISABLE names one detector. DISABLE_ALL=1 turns every detector off.
 * DEVICES defaults to 16, two of each class, the same rotation as the 200-device bench.
 * @returns {void}
 */
function main() {
  const count = Number(process.env.DEVICES || 16);
  const disable = process.env.DISABLE || '';
  const disableAll = process.env.DISABLE_ALL === '1';
  /** @type {Record<string, { enabled: boolean }>} */
  const over = {};
  if (disableAll) {
    for (const id of Object.keys(detectors)) over[id] = { enabled: false };
  } else if (disable) {
    if (!detectors[disable]) throw new Error(`unknown detector ${disable}`);
    over[disable] = { enabled: false };
  }
  const engine = createEngine({ learnMs: 1e14, tiers: TIERS, detectors: over });
  const before = heapUsed();
  let events = 0;
  for (let i = 0; i < count; i++) {
    const profile = CLASS_NAMES[i % CLASS_NAMES.length];
    const id = `rich-${i}`;
    engine.setDeviceClass(id, profile);
    const batch = simulate({ profile, days: 7, seed: i + 1, startTs: 0, rich: true });
    for (const event of batch) {
      engine.feed({ ...event, device: id });
      events += 1;
    }
  }
  engine.lock();
  const heap = heapUsed() - before;
  const devices = engine.stats().devices;
  process.stdout.write(
    `${JSON.stringify({
      disable: disableAll ? '*' : disable || null,
      devices,
      events,
      heapBytes: heap,
      kb: devices > 0 ? heap / devices / 1024 : 0,
    })}\n`,
  );
}

main();
