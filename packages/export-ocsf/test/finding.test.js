'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { toFinding } = require('../src/index.js');

test('maps an anomaly to a Detection Finding', () => {
  const finding = toFinding({
    id: '1',
    device: 'cam-1',
    detector: 'cert-change',
    severity: 'high',
    confidence: 0.9,
    ts: 1000,
    actual: 'Unexpected CA',
    expected: 'Vendor CA',
    attack: ['T1557'],
  });
  assert.strictEqual(finding.class_uid, 2004);
  assert.strictEqual(finding.type_uid, 200401);
  assert.strictEqual(finding.severity_id, 4);
  assert.strictEqual(finding.finding_info.title, 'cert-change');
  assert.strictEqual(finding.device.uid, 'cam-1');
  assert.deepStrictEqual(finding.attacks, ['T1557']);
  assert.strictEqual(finding.metadata.version, '1.4.0');
});

const fixture = require('./fixtures/detection-finding-1.4.0.js');

test('an anomaly and an escalated incident match the 1.4.0 fixture', () => {
  const anomaly = toFinding({
    id: '9',
    fingerprint: '0123456789abcdef',
    device: 'cam-1',
    detector: 'dns-rebinding',
    severity: 'high',
    confidence: 0.9,
    ts: 50,
    actual: 'kim.example -> 0.0.0.0',
    expected: 'a public answer',
    attack: ['T1557'],
    evidence: { events: 1, sample: [{ qname: 'kim.example' }] },
  });
  for (const key of fixture.required) assert.ok(Object.hasOwn(anomaly, key));
  assert.strictEqual(anomaly.class_uid, fixture.class_uid);
  assert.strictEqual(anomaly.category_uid, fixture.category_uid);
  assert.strictEqual(anomaly.activity_id, fixture.create.activity_id);
  assert.strictEqual(anomaly.type_uid, fixture.create.type_uid);
  assert.strictEqual(anomaly.finding_info.uid, '0123456789abcdef');
  assert.deepStrictEqual(anomaly.finding_info.attacks, [{ technique: { uid: 'T1557' } }]);
  assert.deepStrictEqual(anomaly.evidences, [{ data: { qname: 'kim.example' } }]);

  const incident = toFinding({
    id: 'i1',
    device: 'cam-1',
    severity: 'critical',
    ts: 80,
    anomalyIds: ['1', '2'],
    summary: 'cam-1 contacted a new domain, then scanned',
    score: 90,
  });
  for (const key of fixture.required) assert.ok(Object.hasOwn(incident, key));
  assert.strictEqual(incident.activity_id, fixture.update.activity_id);
  assert.strictEqual(incident.type_uid, fixture.update.type_uid);
  assert.strictEqual(incident.evidences, undefined);

  const pinned = toFinding({ id: '1', severity: 'low', ts: 1 }, { ocsfVersion: '1.6.0' });
  assert.strictEqual(pinned.metadata.version, '1.6.0');
});
