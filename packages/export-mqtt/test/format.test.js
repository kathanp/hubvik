'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { toMessages, publishWith } = require('../src/index.js');

test('mqtt topics follow the record kind', () => {
  const anomaly = toMessages({
    id: '1',
    device: 'cam',
    detector: 'fan-out',
    severity: 'high',
    ts: 5,
  });
  assert.strictEqual(anomaly[0].topic, 'hubvik/anomaly/cam/fan-out');
  /** @type {string[]} */
  const topics = [];
  const count = publishWith((topic) => topics.push(topic), { id: 'c1', devices: ['a'], edges: [] });
  assert.strictEqual(count, 1);
  assert.strictEqual(topics[0], 'hubvik/campaign/c1');
  const wild = toMessages({ id: '1', device: 'cam/#', detector: 'a+b' });
  assert.strictEqual(wild[0].topic, 'hubvik/anomaly/cam/ab');
});
