'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');

const HOUR = 3600000;

test('scoring lr and alerts stay off the default anomaly stream', () => {
  const plain = createEngine();
  const extra = createEngine({ scoring: 'lr', alerts: true });
  const events = [];
  for (let i = 0; i < 20; i += 1) {
    events.push({
      ts: i * 1000,
      kind: 'flow',
      device: 'cam',
      dst: `1.2.3.${i}`,
      dstPort: 443,
      proto: 'tcp',
      bytesOut: 100,
      bytesIn: 100,
      packets: 1,
    });
  }
  for (const engine of [plain, extra]) {
    for (const event of events) engine.feed(event);
  }
  assert.strictEqual(plain.stats().anomalyCount, extra.stats().anomalyCount);
});

test('a maintenance annotation skips incident score for a listed detector', () => {
  const engine = createEngine({ alerts: true });
  const seen = [];
  engine.on('alert', (row) => seen.push(row));
  engine.feed({
    ts: HOUR,
    kind: 'flow',
    device: 'cam',
    dst: '1.1.1.1',
    dstPort: 80,
    proto: 'tcp',
    bytesOut: 1,
    bytesIn: 1,
    packets: 1,
  });
  engine.annotate('cam', {
    kind: 'maintenance',
    fromTs: HOUR,
    untilTs: HOUR * 3,
    detectors: ['new-destination'],
  });
  engine.feed({
    ts: HOUR + 1000,
    kind: 'flow',
    device: 'cam',
    dst: '9.9.9.9',
    dstPort: 443,
    proto: 'tcp',
    bytesOut: 1,
    bytesIn: 1,
    packets: 1,
  });
  const body = engine.checkpoint();
  const copy = createEngine();
  copy.restore(body);
  assert.ok(copy.annotations({ device: 'cam' }).length >= 1);
  assert.ok(Array.isArray(seen));
});

test('loadTemplates rejects an unknown detector', () => {
  const engine = createEngine();
  assert.throws(
    () =>
      engine.loadTemplates([
        { id: 'x', steps: [{ detector: 'not-a-detector' }], within: '1h', by: 'device' },
      ]),
    (err) => err.code === 'TEMPLATE_INVALID',
  );
});

function summary(ts, device, dst) {
  return { ts, device, dst, bytes: 20 };
}

test('a maintenance window skips scoring and a hard rule still alerts', () => {
  const quiet = createEngine({ alerts: true });
  const loud = createEngine({ alerts: true, tiers: ['T0', 'T1'] });
  const alerts = [];
  loud.on('alert', (row) => alerts.push(row));
  quiet.feed(summary(1000, 'cam', '1.1.1.1'));
  quiet.lock('cam');
  quiet.annotate('cam', {
    kind: 'maintenance',
    fromTs: 1000,
    untilTs: 1000 + 3600000,
    detectors: ['new-destination'],
  });
  const tagged = [];
  quiet.on('anomaly', (row) => tagged.push(row));
  quiet.feed(summary(2000, 'cam', '9.9.9.9'));
  assert.strictEqual(tagged.length, 1);
  assert.ok(tagged[0].context);
  assert.strictEqual(tagged[0].incidentId, undefined);
  loud.feed(summary(1000, 'cam', '1.1.1.1'));
  loud.lock('cam');
  loud.annotate('cam', { kind: 'maintenance', fromTs: 1000, untilTs: 1000 + 3600000 });
  loud.feed({
    ts: 2000,
    type: 'flow',
    device: 'cam',
    srcIp: '10.1.0.9',
    srcPort: 0,
    dstIp: '10.1.0.1',
    dstPort: 0,
    proto: 'icmp',
    direction: 'in',
    bytesOut: 0,
    bytesIn: 28,
    pktsOut: 0,
    pktsIn: 1,
    durationMs: 1,
    icmpType: 5,
  });
  assert.ok(alerts.some((row) => row.kind === 'hard-rule'));
});

test('safety criticality changes alerts and not the anomaly stream', () => {
  function run(level) {
    const engine = createEngine({ alerts: true });
    const anomalies = [];
    const alerts = [];
    engine.on('anomaly', (row) => anomalies.push(JSON.stringify(row)));
    engine.on('alert', (row) => alerts.push(row));
    engine.feed(summary(1000, 'cam', '1.1.1.1'));
    engine.lock('cam');
    if (level) engine.setDeviceCriticality('cam', level);
    for (const dst of ['2.2.2.2', '3.3.3.3', '4.4.4.4']) engine.feed(summary(2000, 'cam', dst));
    return { anomalies, alerts: alerts.length };
  }
  const normal = run('normal');
  const safety = run('safety');
  assert.deepStrictEqual(normal.anomalies, safety.anomalies);
  assert.strictEqual(normal.alerts, 0);
  assert.ok(safety.alerts >= 1);
});

test('audit restore warns when the chain is broken', () => {
  const engine = createEngine({ audit: true });
  engine.feed(summary(1000, 'cam', '1.1.1.1'));
  engine.setDeviceClass('cam', 'camera');
  const body = engine.checkpoint();
  body.audit.records[0].hash = '0'.repeat(64);
  const copy = createEngine({ audit: true });
  const warnings = [];
  copy.on('warning', (row) => warnings.push(row.code));
  copy.restore(body);
  assert.ok(warnings.includes('AUDIT_BROKEN'));
});

test('peer suggestion does not call setPeerGroup', () => {
  const engine = createEngine({ peerSuggest: true });
  const warnings = [];
  engine.on('warning', (row) => warnings.push(row.code));
  for (const id of ['a', 'b', 'c']) engine.feed(summary(1000, id, 'cdn.example.com'));
  engine.lock();
  const stats = engine.stats();
  assert.ok(stats.peerSuggestions.length >= 1);
  assert.ok(warnings.includes('PEER_GROUP_SUGGESTED'));
  const baseline = engine.exportBaseline({ createdAt: 0 });
  for (const id of ['a', 'b', 'c']) assert.strictEqual(baseline.devices[id].peerGroup, null);
});
