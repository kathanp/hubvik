'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const drift = require('../../src/engine/drift');

const DAY = 86400000;

function summary(ts, device, dst) {
  return { ts, device, dst, bytes: 20 };
}

test('lr scoring records a posterior and ack halves the contribution', () => {
  const engine = createEngine({ scoring: 'lr', alerts: true });
  const incidents = [];
  engine.on('incident', (row) => incidents.push(row));
  engine.feed(summary(1000, 'cam', '1.1.1.1'));
  engine.lock('cam');
  engine.feed(summary(2000, 'cam', '9.9.9.9'));
  const row = incidents.find((item) => Array.isArray(item.contributions));
  assert.ok(row);
  assert.strictEqual(typeof row.posterior, 'number');
  const explained = engine.explain(row.id);
  assert.ok(explained.contributions.length >= 1);
  const before = explained.contributions[0].llr;
  engine.ack(row.anomalyIds[0]);
  const after = incidents[incidents.length - 1];
  assert.ok(after.contributions[0].llr < before);
});

test('a two-step template matches and a short firmware window suggests relearn', () => {
  const engine = createEngine({ alerts: true, scoring: 'lr' });
  const matched = [];
  const warnings = [];
  engine.on('template-match', (row) => matched.push(row));
  engine.on('warning', (row) => warnings.push(row.code));
  engine.loadTemplates([
    {
      id: 'pair',
      steps: [{ detector: 'new-destination' }, { detector: 'new-destination' }],
      within: '1h',
      by: 'device',
      llrBonus: 1,
    },
  ]);
  engine.feed(summary(1000, 'cam', '1.1.1.1'));
  engine.lock('cam');
  engine.annotate('cam', { kind: 'firmware-update', fromTs: 1000, untilTs: 1500 });
  engine.feed(summary(2000, 'cam', '2.2.2.2'));
  engine.feed(summary(3000, 'cam', '3.3.3.3'));
  assert.strictEqual(matched.length, 1);
  assert.ok(warnings.includes('RELEARN_SUGGESTED'));
  const id = engine.annotations({ device: 'cam' })[0].id;
  assert.strictEqual(engine.removeAnnotation(id), true);
  assert.strictEqual(engine.removeAnnotation(id), false);
});

test('annotation abuse, drift across a day, and a folded digest', () => {
  const engine = createEngine({
    alerts: true,
    drift: true,
    audit: true,
    incidentWindowMs: 500,
  });
  const warnings = [];
  const alerts = [];
  engine.on('warning', (row) => warnings.push(row.code));
  engine.on('alert', (row) => alerts.push(row));
  engine.feed(summary(1000, 'cam', '1.1.1.1'));
  engine.lock('cam');
  engine.setDeviceCriticality('cam', 'safety');
  for (let i = 0; i < 11; i += 1) {
    engine.annotate('cam', {
      kind: 'user-action',
      fromTs: 1000,
      untilTs: 2000 + i,
    });
  }
  assert.ok(warnings.includes('ANNOTATION_ABUSE'));
  engine.feed(summary(3000, 'cam', '1.1.1.1'));
  engine.feed(summary(DAY + 3000, 'cam', '1.1.1.1'));
  for (let group = 0; group < 4; group += 1) {
    const start = DAY + 120000 + group * 120000;
    for (let n = 0; n < 3; n += 1) {
      engine.feed(summary(start + n * 100, 'cam', `10.0.${group}.${n}`));
    }
  }
  for (let n = 0; n < 3; n += 1) {
    engine.feed(summary(DAY * 2 + 120000 + n * 100, 'cam', `10.9.9.${n}`));
  }
  assert.ok(alerts.some((row) => row.kind === 'digest'));
  assert.ok(engine.auditLog().length >= 1);
  assert.strictEqual(engine.verifyAudit().ok, true);
  assert.throws(
    () => engine.setDeviceCriticality('cam', 'nope'),
    (err) => err.code === 'CRITICALITY_IS_INVALID',
  );
  assert.throws(
    () => createEngine({ scoring: 'nope' }),
    (err) => err.code === 'SCORING_IS_INVALID',
  );
});

test('templates, peers, and shadow matches exercise the remaining branches', () => {
  const additive = createEngine({ alerts: true, incidentWindowMs: 1 });
  const incidents = [];
  additive.on('incident', (row) => incidents.push(row));
  additive.loadTemplates([
    {
      id: 'pair',
      steps: [{ detector: 'new-destination' }, { detector: 'new-destination' }],
      within: '1h',
      by: 'device',
    },
  ]);
  additive.feed(summary(1000, 'cam', '1.1.1.1'));
  additive.lock('cam');
  additive.feed(summary(2000, 'cam', '2.2.2.2'));
  additive.feed(summary(4000, 'cam', '3.3.3.3'));
  assert.ok(incidents.some((row) => row.severity === 'high'));

  const shadow = createEngine({
    alerts: true,
    peerSuggest: true,
    drift: true,
    tiers: ['T0', 'T1', 'T2'],
    detectors: { 'new-destination': { mode: 'shadow' } },
  });
  shadow.loadTemplates([
    {
      id: 'pair',
      steps: [{ detector: 'new-destination' }, { detector: 'new-destination' }],
      within: '1h',
      by: 'device',
      allowShadow: true,
    },
  ]);
  shadow.feed({
    type: 'dns',
    device: 'cam',
    ts: 1000,
    qname: 'a.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '1.1.1.1', ttl: 30 }],
  });
  shadow.feed({
    type: 'flow',
    device: 'cam',
    ts: DAY + 1000,
    srcIp: '10.1.0.8',
    srcPort: 40000,
    dstIp: '1.1.1.1',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 1000,
    bytesIn: 10,
    pktsOut: 2,
    pktsIn: 1,
    durationMs: 20,
    dstName: 'cdn.example',
  });
  shadow.lock('cam');
  shadow.feed(summary(DAY + 2000, 'cam', '9.9.9.9'));
  shadow.feed(summary(DAY + 3000, 'cam', '8.8.8.8'));
  assert.strictEqual(shadow.explain('missing'), null);

  const same = createEngine({ scoring: 'lr', incidentWindowMs: 60000 });
  same.feed(summary(1000, 'cam', '1.1.1.1'));
  same.lock('cam');
  same.feed(summary(2000, 'cam', '2.2.2.2'));
  same.feed(summary(3000, 'cam', '3.3.3.3'));
  assert.strictEqual(same.explain('missing'), null);
  assert.ok(same.stats().anomalies >= 2);
});

test('drift rejects a bad day and a bad snapshot', () => {
  const state = drift.createDrift('cam');
  assert.throws(
    () => drift.observe(state, 'families', 1, -1, 1),
    (err) => err.code === 'DRIFT_DAY_IS_INVALID',
  );
  assert.throws(
    () => drift.fromJSON(null),
    (err) => err.code === 'DRIFT_STATE_IS_INVALID',
  );
  const raw = drift.toJSON(state);
  raw.families.day = 4;
  raw.families.count = 0;
  assert.throws(
    () => drift.fromJSON(raw),
    (err) => err.code === 'DRIFT_STATE_IS_INVALID',
  );
});
