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
});
