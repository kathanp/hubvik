'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

/**
 * @param {string} qname
 * @param {string} [qtype]
 */
function dns(qname, qtype = 'A') {
  return {
    type: 'dns',
    device: 'cam',
    ts: 1000,
    qname,
    qtype,
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  };
}

test('dns-tunnel scores many names only under one parent', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T2'] });
  /** @type {any[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'dns-tunnel') alerts.push(item);
  });
  for (let i = 0; i < 11; i += 1) engine.feed(dns(`host${i}.other${i}.example`));
  assert.deepStrictEqual(alerts, []);

  const tunnel = createEngine({ learnMs: 0, tiers: ['T2'] });
  /** @type {any[]} */
  const hits = [];
  tunnel.on('anomaly', (item) => {
    if (item.detector === 'dns-tunnel') hits.push(item);
  });
  for (let i = 0; i < 11; i += 1) {
    tunnel.feed(dns(`${'qxvzkplmnbwr'.repeat(4)}${i}.evil.example`, 'TXT'));
  }
  assert.strictEqual(hits.length, 1);
  assert.ok(hits[0].data.score >= 3);
});
