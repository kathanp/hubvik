'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const base = { device: 'd', ts: 1000 };

test('typed events validate and malformed fields are dropped', () => {
  const engine = createEngine({ learnMs: 10_000_000 });
  const warnings = [];
  engine.on('warning', (warning) => warnings.push(warning.message));
  engine.feed({
    ...base,
    type: 'flow',
    srcIp: '10.0.0.1',
    srcPort: 1,
    dstIp: '10.0.0.2',
    dstPort: 80,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 1,
    bytesIn: 2,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 5,
    tcpOutcome: 'established',
    dstName: 'video.vendor.com',
  });
  engine.feed({
    ...base,
    type: 'flow',
    ts: 2000,
    srcIp: '10.0.0.1',
    srcPort: 1,
    dstIp: '10.0.0.2',
    dstPort: 80,
    proto: 'udp',
    direction: 'in',
    bytesOut: 1,
    bytesIn: 1,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 1,
    tcpOutcome: 'nope',
    dstName: '!!!',
  });
  engine.feed({
    ...base,
    type: 'dns',
    ts: 3000,
    qname: 'bücher.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '1.2.3.4', ttl: 30 }, { type: 1 }, null],
  });
  engine.feed({
    ...base,
    type: 'dns',
    ts: 4000,
    qname: 'a.example',
    qtype: 'A',
    rcode: 'NXDOMAIN',
    resolver: '10.0.0.1',
    answers: 'nope',
  });
  engine.feed({
    ...base,
    type: 'tls',
    ts: 5000,
    dstIp: '10.0.0.2',
    dstPort: 443,
    sni: 'video.vendor.com',
    ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
  });
  engine.feed({
    ...base,
    type: 'tls',
    ts: 6000,
    dstIp: '10.0.0.2',
    dstPort: 443,
    sni: '..',
    ja4: 12,
  });
  engine.feed({
    ...base,
    type: 'http',
    ts: 7000,
    dstIp: '10.0.0.2',
    dstPort: 80,
    method: 'GET',
    host: 'video.vendor.com',
    path: '/live',
  });
  engine.feed({
    device: 'd',
    type: 'arp',
    ts: 8000,
    ip: '10.0.0.9',
    mac: 'AA:BB:CC:DD:EE:FF',
    op: 'req',
  });
  engine.feed({ type: 'dhcp', ts: 9000, device: 'd', mac: 'aa:bb:cc:dd:ee:ff', msg: 'discover' });
  engine.feed({
    device: 'd',
    type: 'ra',
    ts: 10000,
    srcMac: 'aa:bb:cc:dd:ee:ff',
    srcIp: 'fe80::1',
    prefixes: ['2001:db8::/64'],
    routerLifetime: 1800,
  });
  engine.feed({
    ...base,
    type: 'discovery',
    ts: 11000,
    proto: 'ssdp',
    srcIp: '10.0.0.9',
    direction: 'lan',
  });
  engine.feed({
    ...base,
    type: 'app',
    ts: 12000,
    proto: 'mqtt',
    role: 'client',
    peerIp: '10.0.0.8',
    op: 'connect',
    target: 'broker',
    value: 1,
    result: 'ok',
  });
  engine.feed({
    ...base,
    type: 'app',
    ts: 13000,
    proto: 'coap',
    role: 'server',
    peerIp: '10.0.0.8',
    op: 'get',
    value: { nope: true },
  });
  assert.ok(warnings.some((message) => message.includes('tcpOutcome')));
  assert.ok(warnings.some((message) => message.includes('dns.answers')));
  assert.strictEqual(engine.stats().devices, 1);
});

test('invalid events and options throw', () => {
  const engine = createEngine();
  assert.throws(() => engine.feed(null), /object/);
  assert.throws(() => engine.feed({ device: '__proto__', ts: 1 }), /reserved/);
  assert.throws(() => engine.feed({ device: 'd', type: 1, ts: 1 }), /type/);
  assert.throws(() => engine.feed({ device: 'd', type: 'flow', ts: 1 }), /requires/);
  assert.throws(
    () =>
      engine.feed({
        ...base,
        type: 'flow',
        srcIp: 'a',
        srcPort: 1,
        dstIp: 'b',
        dstPort: 1,
        proto: 'tcp',
        direction: 'sideways',
        bytesOut: 1,
        bytesIn: 1,
        pktsOut: 1,
        pktsIn: 1,
        durationMs: 1,
      }),
    /direction/,
  );
  assert.throws(
    () =>
      engine.feed({
        ...base,
        type: 'flow',
        srcIp: 'a',
        srcPort: 1,
        dstIp: 'b',
        dstPort: 1,
        proto: 'sctp',
        direction: 'lan',
        bytesOut: 1,
        bytesIn: 1,
        pktsOut: 1,
        pktsIn: 1,
        durationMs: 1,
      }),
    /proto/,
  );
  assert.throws(
    () => engine.feed({ ...base, type: 'dns', qname: ' ', qtype: 'A', rcode: 'X', resolver: 'a' }),
    /qname/,
  );
  assert.throws(
    () => engine.feed({ ...base, type: 'app', proto: 'mqtt', role: 'peer', peerIp: 'a', op: 'x' }),
    /role/,
  );
  assert.throws(
    () =>
      engine.feed({ ...base, type: 'app', proto: 'nope', role: 'client', peerIp: 'a', op: 'x' }),
    /proto/,
  );
  assert.throws(() => createEngine({ tiers: ['T9'] }), /tiers/);
  assert.throws(() => createEngine({ detectors: { 'volume-spike': 'no' } }), /detectors/);
  assert.throws(() => createEngine({ hourOf: 'utc' }), /hourOf/);
  assert.throws(() => createEngine({ windowMs: 1.5 }), /integer/);
  assert.throws(() => createEngine({ sigma: -1 }), /sigma/);
  assert.throws(() => createEngine([]), /options/);
  assert.throws(() => engine.feedBatch('nope'), /array/);
  assert.throws(() => engine.flush(Number.NaN), /flush/);
});

test('allow, suppress, ack, peer group, and detector registration', () => {
  const engine = createEngine({
    learnMs: 1,
    sigma: 2,
    detectors: { 'volume-spike': { severity: 'low', enabled: true } },
  });
  const seen = [];
  engine.use({
    id: 'tap',
    version: 1,
    requires: ['T0'],
    defaults: { severity: 'low' },
    category: 'integrity',
    check(_dev, _ev, ctx) {
      seen.push(ctx.detectorOptions({ id: 'tap', defaults: { severity: 'low' } }).severity);
    },
  });
  engine.setPeerGroup('d', 'cams');
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  engine.lock('d');
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 120_000 });
  engine.allow('d', 'port', '443');
  assert.throws(() => engine.allow('d', 'nope', 'x'), /kind/);
  assert.throws(() => engine.allow('d', 'port', ''), /value/);
  engine.suppress('d', 'new-destination', { untilTs: 50 });
  assert.throws(() => engine.suppress('d', 'new-destination', { untilTs: 'later' }), /untilTs/);
  assert.throws(() => engine.suppress('d', 'new-destination', { match: 1 }), /match/);
  assert.throws(() => engine.suppress('d', 'missing', {}), /unknown detector/);
  engine.ack('1');
  assert.throws(() => engine.ack(''), /anomaly id/);
  assert.throws(() => engine.setPeerGroup('__proto__', 'g'), /device id/);
  assert.throws(() => engine.setPeerGroup('d', 1), /peer group/);
  engine.setPeerGroup('d', null);
  assert.throws(() => engine.use(null), /detector/);
  assert.throws(() => engine.use({ id: 'Bad', version: 1, requires: ['T0'], defaults: {} }), /id/);
  assert.throws(
    () => engine.use({ id: 'x', version: 0, requires: ['T0'], defaults: {} }),
    /version/,
  );
  assert.throws(() => engine.use({ id: 'x', version: 1, requires: [], defaults: {} }), /requires/);
  assert.throws(
    () => engine.use({ id: 'x', version: 1, requires: ['T0'], defaults: null }),
    /defaults/,
  );
  assert.throws(
    () => engine.use({ id: 'tap', version: 1, requires: ['T0'], defaults: {} }),
    /already/,
  );
  assert.ok(seen.includes('low'));
  assert.strictEqual(engine.stats().allows, 1);
  assert.ok(engine.stats().acks >= 1);
});

test('import rejects a broken baseline and respects the device cap', () => {
  const engine = createEngine({ learnMs: 1, maxDevices: 1 });
  engine.feed({ device: 'keep', dst: 'a.example', bytes: 1, ts: 0 });
  const baseline = engine.exportBaseline({ createdAt: 1 });
  const badMac = JSON.parse(JSON.stringify(baseline));
  badMac.sig = { alg: 'HMAC-SHA256', mac: 'abcd' };
  assert.throws(() => engine.importBaseline(badMac, { verify: 'k' }), /signature/);
  const longId = JSON.parse(JSON.stringify(baseline));
  longId.devices['x'.repeat(300)] = longId.devices.keep;
  assert.throws(() => engine.importBaseline(longId), /string too long/);
  const noBlocks = JSON.parse(JSON.stringify(baseline));
  noBlocks.devices.keep.detectors = null;
  assert.throws(() => engine.importBaseline(noBlocks), /detectors/);
  const unknown = JSON.parse(JSON.stringify(baseline));
  unknown.devices.keep.detectors.nope = { v: 1, state: {} };
  assert.throws(() => engine.importBaseline(unknown), /unknown detector/);
  const version = JSON.parse(JSON.stringify(baseline));
  version.devices.keep.detectors['fan-out'].v = 99;
  assert.throws(() => engine.importBaseline(version), /version/);
  const peer = JSON.parse(JSON.stringify(baseline));
  peer.devices.keep.peerGroup = 'p'.repeat(300);
  assert.throws(() => engine.importBaseline(peer), /string too long/);
  const samples = JSON.parse(JSON.stringify(baseline));
  samples.devices.keep.detectors['fan-out'].state = { samples: 'nope' };
  assert.throws(() => engine.importBaseline(samples), /samples/);
  const hours = JSON.parse(JSON.stringify(baseline));
  hours.devices.keep.detectors['wrong-time'].state = { hours: [1, 'x'] };
  assert.throws(() => engine.importBaseline(hours), /hours/);
  const dsts = JSON.parse(JSON.stringify(baseline));
  dsts.devices.keep.detectors['new-destination'].state = null;
  assert.throws(() => engine.importBaseline({ ...dsts, devices: dsts.devices }), /state/);
  const second = createEngine({ learnMs: 1 });
  second.feed({ device: 'other', dst: 'b.example', bytes: 1, ts: 0 });
  const extra = second.exportBaseline({ createdAt: 2 });
  extra.devices.third = extra.devices.other;
  const capped = createEngine({ learnMs: 1, maxDevices: 1 });
  const warnings = [];
  capped.on('warning', (warning) => warnings.push(warning.code));
  capped.importBaseline(extra, { merge: false });
  assert.ok(warnings.includes('STATE_CAP'));
  assert.strictEqual(capped.stats().devices, 1);
});

test('indicator and name edge cases', () => {
  const engine = createEngine({ maxIndicators: 10 });
  assert.throws(() => engine.loadIndicators([{ value: '', type: 'ip', source: 's' }]), /value/);
  assert.throws(
    () => engine.loadIndicators([{ value: 'a.example', type: 'nope', source: 's' }]),
    /type/,
  );
  assert.throws(
    () => engine.loadIndicators([{ value: 'a.example', type: 'domain', source: '' }]),
    /source/,
  );
  assert.throws(
    () => engine.loadIndicators([{ value: '999.1.1.1', type: 'ip', source: 's' }]),
    /ip/,
  );
  engine.loadIndicators([
    { value: '10.1.1.1', type: 'ip', source: 'lab', confidence: 0.5, expiresTs: 10 },
    { value: 'evil.example', type: 'domain', source: 'lab' },
    { value: 't13d', type: 'ja4', source: 'lab' },
  ]);
  assert.strictEqual(engine.stats().indicators, 3);
  const dropped = [];
  engine.on('warning', (warning) => dropped.push(warning));
  engine.feed({ device: 'd', dst: '::ffff:10.2.3.4', bytes: 1, ts: 1 });
  engine.feed({ device: 'd', dst: 'not a host', bytes: Number.NaN, ts: -1 });
  assert.ok(dropped.length >= 1);
});
