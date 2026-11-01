'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

test('profile all leaves a live detector active', () => {
  const engine = createEngine();
  const status = engine.stats().detectors['new-destination'];
  assert.strictEqual(status.active, true);
  assert.notStrictEqual(status.reason, 'profile');
});

test('profile core turns off a live detector that is not in the core list', () => {
  const tiers = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
  const engine = createEngine({ profile: 'core', tiers });
  const status = engine.stats().detectors['new-destination'];
  assert.deepStrictEqual(status, { active: false, reason: 'profile' });
  assert.strictEqual(engine.stats().detectors['horizontal-scan'].active, true);
});

test('detectors[id].enabled wins over the core profile', () => {
  const engine = createEngine({
    profile: 'core',
    detectors: { 'new-destination': { enabled: true } },
  });
  assert.strictEqual(engine.stats().detectors['new-destination'].active, true);
});

test('an unknown profile throws PROFILE_IS_INVALID', () => {
  assert.throws(
    () => createEngine({ profile: 'wide' }),
    (err) => err.code === 'PROFILE_IS_INVALID',
  );
});
