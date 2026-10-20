'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { toText } = require('../src/index.js');

test('prometheus text uses zero for missing stats', () => {
  const text = toText({ events: 3, anomalies: 1 });
  assert.match(text, /iotwarden_events_total 3/);
  assert.match(text, /iotwarden_memory_bytes 0/);
  assert.strictEqual(toText({}).includes('iotwarden_anomalies_total 0'), true);
});
