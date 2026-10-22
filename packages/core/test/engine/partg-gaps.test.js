'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { createEngine } = require('../../src/index.js');
const { advance, compile, createBook } = require('../../src/engine/templates');
const { simulate } = require('../../../../test/fixtures/sim');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

const TEMPLATES = path.join(__dirname, '..', '..', '..', '..', 'examples', 'templates');

test('checkpoint sign is the audit HMAC key', () => {
  const left = createEngine({ audit: true });
  const right = createEngine({ audit: true });
  left.feed({ ts: 1000, device: 'cam', dst: 'a.example', bytes: 10 });
  right.feed({ ts: 1000, device: 'cam', dst: 'a.example', bytes: 10 });
  left.checkpoint({ sign: 'audit-secret', createdAt: 1 });
  right.checkpoint({ sign: 'other-secret', createdAt: 1 });
  left.setDeviceCriticality('cam', 'high');
  right.setDeviceCriticality('cam', 'high');
  const leftLog = left.auditLog();
  const rightLog = right.auditLog();
  assert.ok(leftLog.length >= 1);
  assert.notStrictEqual(leftLog[leftLog.length - 1].hash, rightLog[rightLog.length - 1].hash);
  assert.strictEqual(left.verifyAudit().ok, true);
  const revived = createEngine({ audit: true });
  revived.restore(left.checkpoint({ sign: 'audit-secret', createdAt: 1 }));
  revived.setDeviceCriticality('cam', 'safety');
  assert.strictEqual(revived.verifyAudit().ok, true);
});

/**
 * @param {number} ts
 * @param {string} dstIp
 * @param {number} dstPort
 * @returns {object}
 */
function flow(ts, dstIp, dstPort) {
  return {
    type: 'flow',
    device: 'cam',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp,
    dstPort,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 40,
    bytesIn: 40,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
  };
}

test('criticality is stored in the checkpoint and safety hints stay review', () => {
  const savedEngine = createEngine({ responseHints: true, alerts: true, tiers: ['T0', 'T1'] });
  savedEngine.feed(flow(T0, '10.1.0.1', 443));
  savedEngine.lock('cam');
  savedEngine.setDeviceCriticality('cam', 'safety');
  const saved = savedEngine.checkpoint({ createdAt: 1 });
  assert.strictEqual(saved.criticality.cam, 'safety');
  const scan = (criticality) => {
    const engine = createEngine({ responseHints: true, tiers: ['T0', 'T1'] });
    const hints = [];
    engine.on('anomaly', (row) => {
      if (row.detector === 'horizontal-scan') hints.push(row.response || null);
    });
    engine.feed(flow(T0, '10.1.0.1', 443));
    engine.lock('cam');
    engine.setDeviceCriticality('cam', criticality);
    for (let i = 1; i <= 21; i += 1) engine.feed(flow(T0 + 1000 + i, `10.2.0.${i}`, 80));
    engine.flush(T0 + 60_000);
    return hints;
  };
  const normal = scan('normal');
  const safety = scan('safety');
  assert.ok(normal.some((row) => row && row.some((hint) => hint.action !== 'review')));
  assert.ok(safety.length > 0);
  for (const row of safety) {
    assert.ok(row == null || row.every((hint) => hint.action === 'review'));
  }
  const revived = createEngine({ responseHints: true });
  revived.restore(saved);
  assert.strictEqual(revived._criticality.get('cam'), 'safety');
});

test('went-silent on a safety device alerts at high and the anomaly severity stays', () => {
  const engine = createEngine({ alerts: true });
  engine.feed({ ts: 1000, device: 'lock', dst: 'a.example', bytes: 10 });
  engine.setDeviceCriticality('lock', 'safety');
  const alerts = [];
  engine.on('alert', (row) => alerts.push(row));
  const anomaly = {
    id: 'a1',
    detector: 'went-silent',
    severity: 'low',
    device: 'lock',
    actual: 'quiet',
    ts: 1000,
  };
  engine._considerAlert({ id: 'lock' }, null, anomaly, 'incident');
  assert.strictEqual(anomaly.severity, 'low');
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].severity, 'high');
});

test('a template match still alerts after the digest cap', () => {
  const engine = createEngine({ alerts: true });
  const alerts = [];
  engine.on('alert', (row) => alerts.push(row));
  const incident = { id: 'i1', severity: 'low', score: 10, summary: 's', anomalyIds: ['a'] };
  for (let i = 0; i < 4; i += 1) {
    engine._emitAlert('cam', 'incident', 'i1', 'low', 1000 + i, null, incident);
  }
  engine._lastTemplateId = 'dns-c2';
  engine._emitAlert('cam', 'template', 'template:dns-c2', 'high', 5000, null, incident);
  assert.ok(alerts.some((row) => row.template === 'dns-c2'));
});

test('empty signatures do not form a peer cluster', () => {
  const engine = createEngine({ peerSuggest: true });
  for (const id of ['a', 'b', 'c']) {
    engine.feed({ ts: 1000, device: id, dst: '10.0.0.1', bytes: 10 });
  }
  engine.lock();
  assert.deepStrictEqual(engine.stats().peerSuggestions, []);
});

test('30 MB firmware annotation suppresses new-member incidents and a scan still alerts', () => {
  const events = simulate({
    profile: 'camera',
    days: 3,
    seed: 1,
    startTs: T0,
    rich: true,
  });
  const window = events.firmwareUpdate;
  assert.ok(window);
  assert.ok(
    events.some((row) => row.bytesIn === 30_000_000 && row.dstName === 'update.vendor.com'),
  );
  const engine = createEngine({
    alerts: true,
    learnMs: DAY,
    tiers: ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
  });
  const anomalies = [];
  engine.on('anomaly', (row) => anomalies.push(row));
  engine.feed(events[0]);
  engine.annotate(window.target, {
    kind: window.kind,
    fromTs: window.fromTs,
    untilTs: window.untilTs,
    note: window.note,
  });
  for (const event of events.slice(1)) engine.feed(event);
  engine.flush(events[events.length - 1].ts + 60_000);
  const covered = anomalies.filter(
    (row) => row.context && row.ts >= window.fromTs && row.ts < window.untilTs,
  );
  assert.ok(covered.length > 0);
  for (const row of covered) assert.strictEqual(row.incidentId, undefined);

  const scan = createEngine({ alerts: true, tiers: ['T0', 'T1'] });
  const alerts = [];
  scan.on('alert', (row) => alerts.push(row));
  scan.feed(flow(T0, '10.1.0.1', 443));
  scan.lock('cam');
  scan.annotate('cam', {
    kind: 'maintenance',
    fromTs: T0 + 1000,
    untilTs: T0 + 120000,
    note: 'scan window',
  });
  for (let i = 1; i <= 21; i += 1) scan.feed(flow(T0 + 2000 + i, `10.3.0.${i}`, 80));
  scan.flush(T0 + 60_000);
  assert.ok(alerts.some((row) => row.kind === 'hard-rule'));
});

test('learning-period drift width warns on a families step within 3 days', () => {
  const engine = createEngine({ drift: true, learnMs: 8 * DAY, tiers: ['T0'] });
  const warnings = [];
  engine.on('warning', (row) => warnings.push(row));
  const feedDay = (day, families) => {
    const count = families + (day % 2);
    for (let hour = 0; hour < 4; hour += 1) {
      for (let family = 0; family < count; family += 1) {
        engine.feed({
          ts: T0 + day * DAY + hour * H,
          device: 'cam',
          dst: `f${family}.com`,
          bytes: 1000,
        });
      }
    }
  };
  for (let day = 0; day < 7; day += 1) feedDay(day, 4);
  engine.lock('cam');
  for (let day = 7; day < 11; day += 1) feedDay(day, 12);
  engine.flush(T0 + 11 * DAY);
  const drift = warnings.filter(
    (row) => row.code === 'BASELINE_DRIFT' && row.series === 'families',
  );
  assert.ok(drift.length >= 1);
  assert.ok(drift[0].sinceTs <= T0 + 10 * DAY);
});

test('each shipped template matches a direct step replay', () => {
  const files = fs.readdirSync(TEMPLATES).filter((name) => name.endsWith('.json'));
  const known = new Set();
  for (const file of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(TEMPLATES, file), 'utf8'));
    for (const step of raw.steps) for (const id of step.any) known.add(id);
  }
  for (const file of files) {
    const raw = JSON.parse(fs.readFileSync(path.join(TEMPLATES, file), 'utf8'));
    const book = createBook();
    book.templates = compile([raw], known);
    let hits = [];
    raw.steps.forEach((step, index) => {
      hits = hits.concat(
        advance(book, {
          detector: step.any[0],
          device: 'box',
          ts: 1000 * (index + 1),
          id: `a${index}`,
          severity: 'high',
          campaignId: 'c1',
        }),
      );
    });
    assert.strictEqual(hits.length, 1, file);
  }
});

test('Kimwolf network replay is measured and the step chain matches', () => {
  const raw = JSON.parse(fs.readFileSync(path.join(TEMPLATES, 'kimwolf-pivot.json'), 'utf8'));
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T1', 'T2'], alerts: true });
  engine.loadTemplates([raw]);
  const matches = [];
  engine.on('template-match', (row) => matches.push(row.templateId));
  const names = [
    'www.amazon.com',
    'www.walmart.com',
    'www.facebook.com',
    'www.reddit.com',
    'www.ticketmaster.com',
    'www.stubhub.com',
  ];
  names.forEach((dstName, index) => {
    engine.feed({
      type: 'flow',
      device: 'box',
      ts: 1000 + index,
      srcIp: '10.0.0.20',
      srcPort: 42000,
      dstIp: `9.9.0.${index + 1}`,
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 500,
      bytesIn: 2000,
      pktsOut: 4,
      pktsIn: 6,
      durationMs: 100,
      dstName,
    });
  });
  for (let i = 1; i <= 12; i += 1) {
    engine.feed({
      type: 'flow',
      device: 'box',
      ts: 2000,
      srcIp: '10.0.0.20',
      srcPort: 43000 + i,
      dstIp: `10.0.0.${i}`,
      dstPort: 5555,
      proto: 'tcp',
      direction: 'lan',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 20,
    });
  }
  engine.feed({
    type: 'dns',
    device: 'box',
    ts: 3000,
    qname: 'mainnet.infura.io',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  engine.flush(4000);
  assert.strictEqual(matches.length, 0);
  const book = createBook();
  const known = new Set(raw.steps.flatMap((step) => step.any));
  book.templates = compile([raw], known);
  let hits = [];
  raw.steps.forEach((step, index) => {
    hits = hits.concat(
      advance(book, {
        detector: step.any[0],
        device: 'box',
        ts: 1000 * (index + 1),
        id: `k${index}`,
        severity: 'high',
        campaignId: 'c1',
      }),
    );
  });
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].templateId, 'kimwolf-pivot');
});
