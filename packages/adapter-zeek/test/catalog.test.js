'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../core');
const { createParser } = require('../src/index.js');

const BIG = 10 * 1024 * 1024 + 1;

/**
 * @param {Record<string, unknown>} opts
 */
function listen(opts) {
  const eng = createEngine({
    learnMs: 0,
    windowMs: 60000,
    tiers: ['T1', 'T2'],
    shadow: ['port-knock', 'cloud-storage-exfil'],
    ...opts,
  });
  /** @type {string[]} */
  const ids = [];
  eng.on('shadow-anomaly', (row) => ids.push(row.detector));
  return { eng, ids };
}

/**
 * @param {number} ts
 * @param {number} port
 * @param {string} state
 */
function knock(ts, port, state) {
  return JSON.stringify({
    ts,
    uid: `K${port}`,
    id: { orig_h: '8.8.8.8', orig_p: 9, resp_h: '10.0.0.8', resp_p: port },
    proto: 'tcp',
    conn_state: state,
    local_orig: false,
    local_resp: true,
    orig_bytes: 40,
    resp_bytes: 0,
    orig_pkts: 1,
    resp_pkts: 0,
  });
}

test('a Zeek conn log drives port-knock', () => {
  const parser = createParser({ log: 'conn', now: (ts) => ts * 1000 });
  const { eng, ids } = listen({});
  for (const line of [
    knock(10, 1111, 'S0'),
    knock(11, 2222, 'S0'),
    knock(12, 3333, 'REJ'),
    knock(13, 4444, 'SF'),
  ]) {
    for (const event of parser.write(line)) eng.feed(event);
  }
  assert.ok(ids.includes('port-knock'));
});

test('a Zeek dns log and a later conn share a uid only when correlate is on', () => {
  const dns = createParser({ log: 'dns', now: (ts) => ts * 1000 });
  const conn = createParser({ log: 'conn', now: (ts) => ts * 1000 });
  const query = JSON.stringify({
    ts: 30,
    uid: 'Cup',
    id: { orig_h: '10.0.0.8', resp_h: '10.0.0.1' },
    query: 's3.amazonaws.com',
    qtype_name: 'A',
    rcode_name: 'NOERROR',
    answers: ['1.2.3.4'],
  });
  const upload = JSON.stringify({
    ts: 31,
    uid: 'Cup',
    id: { orig_h: '10.0.0.8', orig_p: 40000, resp_h: '3.5.7.9', resp_p: 443 },
    proto: 'tcp',
    conn_state: 'SF',
    local_orig: true,
    orig_bytes: BIG,
    resp_bytes: 100,
    orig_pkts: 10,
    resp_pkts: 2,
  });

  const joined = listen({ correlate: true });
  for (const event of dns.write(query)) joined.eng.feed(event);
  for (const event of conn.write(upload)) joined.eng.feed(event);
  assert.ok(joined.ids.includes('cloud-storage-exfil'));

  const split = listen({ correlate: false });
  for (const event of dns.write(query)) split.eng.feed(event);
  for (const event of conn.write(upload)) split.eng.feed(event);
  assert.strictEqual(split.ids.includes('cloud-storage-exfil'), false);
});
