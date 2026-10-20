'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { toDocument } = require('../src/index.js');

test('ecs documents keep the record timestamp', () => {
  const doc = toDocument({
    ts: 0,
    device: 'cam',
    detector: 'fan-out',
    severity: 'high',
    actual: 'many',
  });
  assert.strictEqual(doc['@timestamp'], '1970-01-01T00:00:00.000Z');
  assert.strictEqual(doc['ecs.version'], '8.11.0');
  const campaign = toDocument({ devices: ['a', 'b'], edges: [{}], summary: 'pivot' });
  assert.deepStrictEqual(campaign.related.hosts, ['a', 'b']);
});
