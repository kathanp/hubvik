'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../core');
const { createParser } = require('../src/index.js');

const BIG = 10 * 1024 * 1024 + 1;

test('a Suricata dns line and a later flow share flow_id when correlate is on', () => {
  const parser = createParser({ now: () => 1000 });
  const query = JSON.stringify({
    event_type: 'dns',
    flow_id: 99,
    src_ip: '10.0.0.8',
    dest_ip: '10.0.0.1',
    dns: { rrname: 's3.amazonaws.com', type: 'A', rcode: 'NOERROR', answers: [] },
  });
  const upload = JSON.stringify({
    event_type: 'flow',
    flow_id: 99,
    timestamp: '2026-01-05T00:00:01.000000+0000',
    src_ip: '10.0.0.8',
    src_port: 40000,
    dest_ip: '3.5.7.9',
    dest_port: 443,
    proto: 'TCP',
    flow: { bytes_toserver: BIG, bytes_toclient: 10, state: 'established', pkts_toserver: 4 },
  });
  const eng = createEngine({
    learnMs: 0,
    windowMs: 60000,
    tiers: ['T1', 'T2'],
    shadow: ['cloud-storage-exfil'],
    correlate: true,
  });
  /** @type {string[]} */
  const ids = [];
  eng.on('shadow-anomaly', (row) => ids.push(row.detector));
  for (const event of parser.write(query)) eng.feed(event);
  for (const event of parser.write(upload)) eng.feed(event);
  assert.ok(ids.includes('cloud-storage-exfil'));
});
