'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, createShardedEngine, HubvikError } = require('../src/index.js');

const DAY = 24 * 60 * 60 * 1000;
const KEY = 'sketch-key';

/**
 * @param {string[]} tiers
 */
function engine(tiers) {
  return createEngine({ learnMs: 40 * DAY, tiers });
}

/**
 * @param {import('../src/index.js').Engine} box
 * @param {string} device
 * @param {number} ts
 * @param {string} dst
 */
function summary(box, device, ts, dst) {
  box.feed({ type: 'summary', device, ts, dst, bytes: 1 });
}

/**
 * @param {import('../src/index.js').Engine} box
 * @param {number} ts
 * @param {string} dstName
 */
function inbound(box, ts, dstName) {
  box.feed({
    type: 'flow',
    device: 'cam',
    ts,
    srcIp: '203.0.113.20',
    srcPort: 443,
    dstIp: '192.0.2.10',
    dstPort: 50000,
    proto: 'tcp',
    direction: 'in',
    bytesOut: 0,
    bytesIn: 100,
    pktsOut: 0,
    pktsIn: 1,
    durationMs: 10,
    dstName,
  });
}

/**
 * @param {string} gatewayId
 * @param {number} day
 * @param {string[]} families
 */
function peer(gatewayId, day, families) {
  const box = engine(['T0']);
  for (const name of families) summary(box, 'cam', day * DAY, `${name}`);
  return box.exportSketch({ key: KEY, gatewayId, fields: ['families'] });
}

test('a sketch carries learned names, and a bad signature changes nothing', () => {
  const box = engine(['T0', 'T1', 'T2']);
  summary(box, 'cam', 0, 'cdn.vendor.example');
  box.feed({
    type: 'dns',
    device: 'cam',
    ts: 0,
    qname: 'cdn.vendor.example',
    qtype: 'A',
    rcode: 0,
    resolver: '192.0.2.53',
  });
  inbound(box, 0, 'cdn.updates.example');
  const before = box.anomalyCount;
  const sketch = box.exportSketch({
    key: KEY,
    gatewayId: 'house',
    fields: ['families', 'resolvers', 'updates', 'beacons'],
    bucketMs: 1000,
  });
  assert.equal(box.anomalyCount, before);
  assert.equal(sketch.kind, 'day');
  assert.equal(sketch.day, 0);
  assert.ok(sketch.families.includes('vendor.example'));
  assert.ok(sketch.resolvers.includes('192.0.2.53'));
  assert.ok(sketch.updates.includes('updates.example'));
  assert.deepEqual(sketch.beacons, []);
  assert.equal(sketch.sig.alg, 'HMAC-SHA256');
  const packed = JSON.stringify(sketch);
  assert.equal(packed.includes('203.0.113.20'), false);
  assert.equal(packed.includes('"cam"'), false);
  const bad = { ...sketch, families: ['evil.example'] };
  box.importSketches([bad], { verify: KEY, cap: 4 });
  const again = box.exportSketch({
    key: KEY,
    gatewayId: 'house',
    fields: ['families'],
  });
  assert.ok(again.families.includes('vendor.example'));
  assert.equal(again.families.includes('evil.example'), false);
  assert.throws(
    () => box.exportSketch({ key: KEY, gatewayId: 'house', fields: ['beacons'] }),
    (err) => err instanceof HubvikError && err.code === 'SKETCH_BUCKET_IS_INVALID',
  );
  assert.throws(
    () => box.importSketches([], { verify: KEY }),
    (err) => err instanceof HubvikError && err.code === 'SKETCH_CAP_IS_INVALID',
  );
});

test('fleet stays off and stays quiet until three peer sketches are loaded', () => {
  const box = engine(['T0']);
  summary(box, 'cam', 0, 'old.example');
  summary(box, 'cam', DAY, 'new.example');
  box.exportSketch({ key: KEY, gatewayId: 'house', fields: ['families'] });
  const quiet = box.fleet();
  assert.deepEqual(quiet, { on: false, rows: [] });
  assert.deepEqual(box.fleet({ on: true }), { on: true, rows: [] });
  const peers = ['b', 'c', 'd'].flatMap((id) => [
    peer(id, 0, ['rare.example']),
    peer(id, 1, ['rare.example', 'new.example', 'overlap.example']),
  ]);
  box.importSketches(peers, { verify: KEY, cap: 8 });
  const report = box.fleet({ on: true });
  const kinds = report.rows.filter((row) => row.field === 'families');
  assert.ok(
    kinds.some((row) => row.kind === 'new-here-common-peers' && row.name === 'new.example'),
  );
  assert.ok(
    kinds.some((row) => row.kind === 'overlap-absent-yesterday' && row.name === 'overlap.example'),
  );
});

test('a rare local family is named only when peers do not have it', () => {
  const box = engine(['T0']);
  summary(box, 'cam', 0, 'rare.example');
  box.exportSketch({ key: KEY, gatewayId: 'house', fields: ['families'] });
  summary(box, 'cam', DAY, 'rare.example');
  box.exportSketch({ key: KEY, gatewayId: 'house', fields: ['families'] });
  const peers = ['b', 'c', 'd'].flatMap((id) => [
    peer(id, 0, ['other.example']),
    peer(id, 1, ['other.example']),
  ]);
  box.importSketches(peers, { verify: KEY, cap: 8 });
  const report = box.fleet({ on: true });
  assert.ok(
    report.rows.some(
      (row) => row.kind === 'rare-here-rare-peers' && row.name === 'rare.example' && row.day === 1,
    ),
  );
  const tampered = { ...peers[1], families: ['rare.example'] };
  box.importSketches([tampered], { verify: KEY, cap: 8 });
  assert.ok(
    box
      .fleet({ on: true })
      .rows.some((row) => row.kind === 'rare-here-rare-peers' && row.name === 'rare.example'),
  );
});

test('the cap and a stale sketch change nothing', () => {
  const box = engine(['T0']);
  summary(box, 'cam', 10 * DAY, 'later.example');
  const fresh = peer('peer', 10, ['later.example']);
  const other = peer('other', 10, ['other.example']);
  const stale = peer('old', 0, ['stale.example']);
  assert.throws(
    () => box.importSketches([fresh, other], { verify: KEY, cap: 1 }),
    (err) => err instanceof HubvikError && err.code === 'ARRAY_SKETCHES_EXCEEDS_CAP',
  );
  box.importSketches([stale], { verify: KEY, cap: 1 });
  box.importSketches([fresh], { verify: KEY, cap: 1 });
  assert.deepEqual(box.fleet({ on: true }).rows, []);
});

test('an allow sketch drops a known update family and a bad allow sketch does not', () => {
  const box = engine(['T0', 'T1']);
  inbound(box, DAY, 'cdn.updates.example');
  box.exportSketch({ key: KEY, gatewayId: 'house', fields: ['updates'] });
  const peers = ['b', 'c', 'd'].map((id) => {
    const peerBox = engine(['T0', 'T1']);
    peerBox.feed({
      type: 'flow',
      device: 'cam',
      ts: DAY,
      srcIp: '203.0.113.20',
      srcPort: 443,
      dstIp: '192.0.2.10',
      dstPort: 50000,
      proto: 'tcp',
      direction: 'in',
      bytesOut: 0,
      bytesIn: 100,
      pktsOut: 0,
      pktsIn: 1,
      durationMs: 10,
      dstName: 'cdn.updates.example',
    });
    return peerBox.exportSketch({ key: KEY, gatewayId: id, fields: ['updates'] });
  });
  box.importSketches(peers, { verify: KEY, cap: 8 });
  const before = box.fleet({ on: true });
  assert.ok(before.rows.some((row) => row.field === 'updates' && row.name === 'updates.example'));
  const allow = box.exportAllowSketch({ key: KEY, updates: ['updates.example'] });
  const bad = { ...allow, updates: ['other.example'] };
  assert.deepEqual(box.importAllowSketch(bad, { verify: KEY }).updates, []);
  assert.deepEqual(box.importAllowSketch(allow, { verify: KEY }).updates, ['updates.example']);
  const after = box.fleet({ on: true });
  assert.equal(
    after.rows.some((row) => row.field === 'updates' && row.name === 'updates.example'),
    false,
  );
});

test('a sharded engine exports one sketch for families on any shard', () => {
  const box = createShardedEngine({ inline: true, shards: 2, learnMs: 40 * DAY, tiers: ['T0'] });
  summary(box, 'cam', 0, 'cdn.vendor.example');
  const sketch = box.exportSketch({ key: KEY, gatewayId: 'house', fields: ['families'] });
  assert.ok(sketch.families.includes('vendor.example'));
  assert.deepEqual(box.fleet(), { on: false, rows: [] });
});
