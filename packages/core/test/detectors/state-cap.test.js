'use strict';

const test = require('node:test');
const assert = require('node:assert');
const detector = require('../../src/detectors/state-cap.js');

test('state-cap names the cap when the engine omits one, then stays quiet', () => {
  const dev = detector.createState();
  const ev = { ts: 1 };
  const ctx = { options: { severity: 'medium' }, extra: { kind: 'state-cap' } };
  const row = detector.check(dev, ev, ctx);
  assert.strictEqual(row.data.cap, 'devices');
  assert.strictEqual(detector.check(dev, ev, ctx), undefined);
  assert.strictEqual(detector.check(dev, ev, { options: {}, extra: null }), undefined);
  detector.importState(dev, null);
  assert.strictEqual(dev.fired, false);
  detector.importState(dev, { fired: true });
  assert.strictEqual(detector.exportState(dev).fired, true);
  assert.strictEqual(detector.memoryEstimate(), 8);
});
