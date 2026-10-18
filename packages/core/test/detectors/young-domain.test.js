'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../../src/index.js');

/**
 * @param {Record<string, unknown>[]} [list]
 */
function engine(list) {
  /** @type {Record<string, { enabled: boolean }>} */
  const options = { 'young-domain': { enabled: true } };
  for (const id of Object.keys(detectors)) {
    if (id !== 'young-domain' && id !== 'threat-intel-match') options[id] = { enabled: false };
  }
  const box = createEngine({
    learnMs: 0,
    tiers: ['T0', 'T2'],
    detectors: options,
  });
  if (list) box.loadIndicators(list);
  return box;
}

/**
 * @param {string} qname
 * @param {number} [ts]
 */
function dns(qname, ts = 1_000) {
  return {
    type: 'dns',
    device: 'd',
    ts,
    qname,
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
  };
}

const listed = {
  value: 'fresh.example',
  type: 'young-domain',
  source: 'lab',
  confidence: 0.8,
};

test('young-domain matches a name and a subdomain, and ignores expiry and an empty list', () => {
  const hit = engine([listed]);
  /** @type {any[]} */
  const alerts = [];
  hit.on('shadow-anomaly', (row) => {
    if (row.detector === 'young-domain') alerts.push(row);
  });
  hit.feed(dns('fresh.example'));
  hit.feed(dns('a.fresh.example', 2_000));
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'medium');
  assert.strictEqual(alerts[0].data.family, 'fresh.example');

  const child = engine([listed]);
  /** @type {any[]} */
  const childAlerts = [];
  child.on('shadow-anomaly', (row) => {
    if (row.detector === 'young-domain') childAlerts.push(row);
  });
  child.feed(dns('a.fresh.example'));
  assert.strictEqual(childAlerts.length, 1);
  assert.strictEqual(childAlerts[0].severity, 'medium');

  const expired = engine([{ ...listed, expiresTs: 1_000 }]);
  /** @type {any[]} */
  const none = [];
  expired.on('shadow-anomaly', (row) => {
    if (row.detector === 'young-domain') none.push(row);
  });
  expired.feed(dns('fresh.example', 1_000));
  assert.deepStrictEqual(none, []);

  const empty = engine();
  empty.on('shadow-anomaly', (row) => none.push(row));
  empty.feed(dns('fresh.example', 2_000));
  assert.deepStrictEqual(none, []);
});

test('young-domain and threat-intel-match score once in an incident', () => {
  const box = engine([
    listed,
    { value: 'fresh.example', type: 'domain', source: 'lab', confidence: 1 },
  ]);
  /** @type {any[]} */
  const alerts = [];
  /** @type {any[]} */
  const incidents = [];
  /** @type {any[]} */
  const shadows = [];
  box.on('anomaly', (row) => alerts.push(row));
  box.on('shadow-anomaly', (row) => shadows.push(row));
  box.on('incident', (row) => incidents.push(row));
  box.feed(dns('fresh.example', 5_000));
  assert.deepStrictEqual(
    alerts.map((row) => row.detector),
    ['threat-intel-match'],
  );
  assert.strictEqual(shadows.length, 1);
  assert.strictEqual(shadows[0].detector, 'young-domain');
  assert.strictEqual(shadows[0].shadow, true);
  assert.strictEqual(shadows[0].incidentId, undefined);
  assert.strictEqual(incidents.at(-1).anomalyIds.length, 1);
  assert.strictEqual(incidents.at(-1).score, 80);
  assert.strictEqual(box.stats().shadow['young-domain'].wouldJoinIncident, 1);
});

test('young-domain caps families at 1,000 and restores them', () => {
  const names = Array.from({ length: 1001 }, (_, i) => ({
    value: `n${i}.example`,
    type: 'young-domain',
    source: 'lab',
    confidence: 0.8,
  }));
  const box = engine(names);
  /** @type {any[]} */
  const alerts = [];
  box.on('shadow-anomaly', (row) => {
    if (row.detector === 'young-domain') alerts.push(row);
  });
  for (let i = 0; i < 1001; i++) box.feed(dns(`n${i}.example`, 1_000 + i));
  assert.strictEqual(alerts.length, 1001);
  const saved = box.exportBaseline({ createdAt: 1 });
  const families = saved.devices.d.detectors['young-domain'].state.families;
  assert.strictEqual(families.length, 1000);
  const next = engine(names);
  next.importBaseline(saved);
  /** @type {any[]} */
  const again = [];
  next.on('shadow-anomaly', (row) => {
    if (row.detector === 'young-domain') again.push(row);
  });
  next.feed(dns('n1000.example', 2_000));
  assert.strictEqual(again.length, 0);
  const bloated = structuredClone(saved);
  const one = bloated.devices.d.detectors['young-domain'].state.families[0];
  bloated.devices.d.detectors['young-domain'].state.families = Array.from(
    { length: 1001 },
    (_, i) => ({
      family: `x${i}.example`,
      ts: one.ts,
    }),
  );
  assert.throws(() => engine().importBaseline(bloated), /exceeds cap/);
});
