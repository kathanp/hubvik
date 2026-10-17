'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

test('a new master writes a setpoint out of range and then silences the controller', () => {
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T5'] });
  for (const value of [20, 21, 22]) {
    engine.feed(app(1000 + value, '10.0.0.2', 'WriteProperty', 'setpoint', value));
  }
  engine.lock('ahu-1');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed(app(5000, '10.0.0.9', 'WriteProperty', 'setpoint', 21));
  engine.feed(app(6000, '10.0.0.2', 'WriteProperty', 'setpoint', 40));
  engine.feed(app(7000, '10.0.0.9', 'DeviceCommunicationControl', 'device'));
  const ids = new Set(anomalies.map((item) => item.detector));
  assert.ok(ids.has('ot-new-master'));
  assert.ok(ids.has('ot-value-out-of-range'));
  assert.ok(ids.has('ot-dangerous-op'));
  assert.ok(anomalies.find((item) => item.detector === 'ot-dangerous-op').hardRule === false);
});

/**
 * @param {number} ts
 * @param {string} peer
 * @param {string} op
 * @param {string} target
 * @param {number | string} [value]
 */
function app(ts, peer, op, target, value) {
  return {
    type: 'app',
    device: 'ahu-1',
    ts,
    proto: 'bacnet',
    role: 'server',
    peerIp: peer,
    op,
    target,
    value,
    result: 'ok',
  };
}
