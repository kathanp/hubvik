'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { T0, DAY } = require('../../../../test/fixtures/clock');

test('group A and B options do not change the anomaly stream or baseline', () => {
  const events = [];
  for (let i = 0; i < 12; i += 1) {
    events.push({
      ts: T0 + i * 1000,
      device: 'cam',
      dst: `host${i % 3}.example.com`,
      bytes: 100 + i,
    });
  }
  const run = (opts) => {
    const engine = createEngine({ learnMs: DAY, tiers: ['T0'], ...opts });
    const anomalies = [];
    engine.on('anomaly', (row) => {
      const copy = JSON.parse(JSON.stringify(row));
      delete copy.context;
      delete copy.llr;
      delete copy.criticality;
      anomalies.push(copy);
    });
    for (const event of events) engine.feed(event);
    engine.lock('cam');
    return {
      anomalies,
      baseline: JSON.stringify(engine.exportBaseline({ createdAt: 1, devices: ['cam'] })),
    };
  };
  const plain = run({});
  const extra = run({
    scoring: 'lr',
    alerts: true,
    drift: true,
    audit: true,
    peerSuggest: true,
  });
  assert.deepStrictEqual(extra.anomalies, plain.anomalies);
  assert.strictEqual(extra.baseline, plain.baseline);
});
