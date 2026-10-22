'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {Record<string, unknown>} [opts]
 */
function engine(opts = {}) {
  return createEngine({ shadow: true, learnMs: 5_000, tiers: TIERS, ...opts });
}

/**
 * @param {any} eng
 * @param {string} id
 */
function listen(eng, id) {
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === id) hits.push(row);
  });
  return hits;
}

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1_000,
    srcIp: '10.0.0.2',
    srcPort: 40_000,
    dstIp: '8.8.8.8',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 100,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
    dstName: 'update.vendor.com',
    ...extra,
  };
}

test('dhcp-route-injection fires on a new option 121 route', () => {
  const eng = engine();
  const hits = listen(eng, 'dhcp-route-injection');
  eng.feed({
    type: 'dhcp',
    device: 'd',
    ts: 1_000,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'offer',
    serverIp: '192.0.2.1',
    options: [53, 1],
  });
  eng.feed({
    type: 'dhcp',
    device: 'd',
    ts: 6_000,
    mac: 'aa:bb:cc:dd:ee:01',
    msg: 'ack',
    serverIp: '192.0.2.1',
    options: [121],
    routes: ['0.0.0.0/0'],
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
  assert.equal(hits[0].data.serverIp, '192.0.2.1');
  const saved = eng.exportBaseline({ createdAt: 1 });
  assert.throws(
    () =>
      eng.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: {
              ...saved.devices.d.detectors,
              'dhcp-route-injection': {
                v: 1,
                state: { ips: Array.from({ length: 65 }, () => '8.8.8.8') },
              },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('wpad-hijack fires when a learned NXDOMAIN name starts answering', () => {
  const eng = engine();
  const hits = listen(eng, 'wpad-hijack');
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'wpad.vendor.com',
    qtype: 'A',
    rcode: 'NXDOMAIN',
    resolver: '192.0.2.1',
  });
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 6_000,
    qname: 'wpad.vendor.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
    answers: [{ type: 'A', value: '198.51.100.9', ttl: 30 }],
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
});

test('ra-flood fires at 50 advertisements in one window', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'ra-flood');
  for (let i = 0; i < 50; i += 1) {
    eng.feed({
      type: 'ra',
      device: 'd',
      ts: 1_000,
      srcMac: 'aa:bb:cc:dd:ee:10',
      srcIp: 'fe80::1',
      prefixes: ['2001:db8::/64'],
      routerLifetime: 1800,
      count: 1,
    });
  }
  assert.equal(hits.length, 1);
  assert.equal(hits[0].data.macs[0], 'aa:bb:cc:dd:ee:10');
});

test('karma-responder fires when one BSSID answers five SSIDs', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'karma-responder');
  for (let i = 0; i < 5; i += 1) {
    eng.feed({
      type: 'wifi',
      device: 'd',
      ts: 1_000,
      mac: 'aa:bb:cc:dd:ee:01',
      bssid: 'aa:bb:cc:dd:ee:f1',
      ssid: `net-${i}`,
      op: 'probe-resp',
    });
  }
  assert.equal(hits.length, 1);
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = engine({ learnMs: 0 });
  next.importBaseline(saved);
  const again = listen(next, 'karma-responder');
  next.feed({
    type: 'wifi',
    device: 'd',
    ts: 2_000,
    mac: 'aa:bb:cc:dd:ee:01',
    bssid: 'aa:bb:cc:dd:ee:f2',
    ssid: 'only',
    op: 'probe-resp',
  });
  assert.equal(again.length, 0);
});

test('cname-cloak fires when a learned name aliases a tracker', () => {
  const eng = engine();
  eng.loadIndicators([{ value: 'tracker.test', type: 'tracker', source: 'test', confidence: 1 }]);
  const hits = listen(eng, 'cname-cloak');
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'www.vendor.test',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
  });
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 6_000,
    qname: 'www.vendor.test',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
    answers: [{ type: 'CNAME', value: 'ads.tracker.test', ttl: 30 }],
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'medium');
});

test('ja4-churn fires on four fingerprints to one server', () => {
  const eng = engine();
  const hits = listen(eng, 'ja4-churn');
  eng.feed({
    type: 'tls',
    device: 'd',
    ts: 1_000,
    dstIp: '8.8.8.8',
    dstPort: 443,
    ja4: 'a',
    sni: 'a.vendor.com',
  });
  for (let i = 0; i < 4; i += 1) {
    eng.feed({
      type: 'tls',
      device: 'd',
      ts: 6_000,
      dstIp: '8.8.8.8',
      dstPort: 443,
      ja4: `b${i}`,
      sni: 'a.vendor.com',
    });
  }
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
});

test('lan-first-seen-domain reports a family absent from both filters', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'lan-first-seen-domain');
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 1_000,
    qname: 'new.example.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
  });
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 1_100,
    qname: 'new.example.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '192.0.2.1',
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'low');
});

test('dormant-reactivation fires after a week of silence and a new family', () => {
  const eng = engine({ learnMs: 3 * DAY });
  const hits = listen(eng, 'dormant-reactivation');
  for (let day = 0; day < 3; day += 1) {
    eng.feed({ ts: day * DAY, device: 'd', dst: 'known.example.com', bytes: 10 });
  }
  const saved = eng.exportBaseline({ createdAt: 1 });
  eng.feed({ ts: 10 * DAY, device: 'd', dst: 'fresh.example.net', bytes: 10 });
  assert.equal(hits.length, 1);
  const next = engine({ learnMs: 0 });
  next.importBaseline(saved);
  const again = listen(next, 'dormant-reactivation');
  next.feed({ ts: 10 * DAY, device: 'd', dst: 'fresh.example.net', bytes: 10 });
  assert.equal(again.length, 1);
});

test('firmware-size-divergence fires when one peer downloads a different image', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'firmware-size-divergence');
  for (const id of ['a', 'b', 'c'])
    eng.feed({ ts: 1_000, device: id, dst: 'update.vendor.com', bytes: 10 });
  eng.setPeerGroup('a', 'cams');
  eng.setPeerGroup('b', 'cams');
  eng.setPeerGroup('c', 'cams');
  const image = (device, bytesIn) =>
    eng.feed(flow({ device, ts: 2_000, direction: 'in', bytesIn, dstName: 'update.vendor.com' }));
  image('a', 2_000_000);
  image('b', 2_000_000);
  image('c', 4_000_000);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].device, 'c');
});

test('stun-turn-relay fires on a new relay above 5 MB', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'stun-turn-relay');
  eng.feed(flow({ dstPort: 3478, dstName: 'stun.example.com', bytesOut: 6_000_000 }));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'medium');
});

test('port-knock fires when a public source opens a port after three knocks', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'port-knock');
  for (const dstPort of [10, 20, 30]) {
    eng.feed(
      flow({ direction: 'in', srcIp: '8.8.8.8', dstPort, tcpOutcome: 'rejected', ts: 1_000 }),
    );
  }
  eng.feed(
    flow({
      direction: 'in',
      srcIp: '8.8.8.8',
      dstPort: 4444,
      tcpOutcome: 'established',
      ts: 2_000,
    }),
  );
  assert.equal(hits.length, 1);
  const saved = eng.exportBaseline({ createdAt: 1 });
  assert.throws(() => {
    const seen = [];
    for (let i = 0; i < 257; i += 1) seen.push(`1.2.3.${i}`);
    eng.importBaseline({
      ...saved,
      devices: {
        d: {
          ...saved.devices.d,
          detectors: {
            ...saved.devices.d.detectors,
            'port-knock': { v: 1, state: { seen } },
          },
        },
      },
    });
  }, /exceeds cap/);
});

test('bacnet-bbmd-write fires for an unlearned foreign-device registration', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'bacnet-bbmd-write');
  eng.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'bacnet',
    role: 'server',
    peerIp: '192.0.2.8',
    op: 'Register-Foreign-Device',
  });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'critical');
});

test('modbus-unit-sweep fires on 16 unit ids when the learned maximum is low', () => {
  const eng = engine();
  const hits = listen(eng, 'modbus-unit-sweep');
  eng.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'modbus',
    role: 'server',
    peerIp: '192.0.2.9',
    op: 'Read',
    unitId: 1,
  });
  for (let unit = 0; unit < 16; unit += 1) {
    eng.feed({
      type: 'app',
      device: 'd',
      ts: 6_000,
      proto: 'modbus',
      role: 'server',
      peerIp: '192.0.2.9',
      op: 'Read',
      unitId: unit,
    });
  }
  assert.equal(hits.length, 1);
});

test('mqtt-retained-command fires on a retained command from a new client', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'mqtt-retained-command');
  eng.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'mqtt',
    role: 'client',
    peerIp: '192.0.2.10',
    op: 'PUBLISH',
    target: 'home/cmd/arm',
    flags: ['retain'],
  });
  assert.equal(hits.length, 1);
});

test('rtsp-new-viewer fires for a client that never pulled the stream', () => {
  const eng = engine({ learnMs: 0 });
  const hits = listen(eng, 'rtsp-new-viewer');
  eng.feed({
    type: 'app',
    device: 'd',
    ts: 1_000,
    proto: 'rtsp',
    role: 'server',
    peerIp: '192.0.2.11',
    op: 'PLAY',
  });
  assert.equal(hits.length, 1);
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = engine({ learnMs: 0 });
  next.importBaseline(saved);
  const again = listen(next, 'rtsp-new-viewer');
  next.feed({
    type: 'app',
    device: 'd',
    ts: 2_000,
    proto: 'rtsp',
    role: 'server',
    peerIp: '192.0.2.11',
    op: 'PLAY',
  });
  assert.equal(again.length, 0);
});

test('suppression-abuse fires after 20 allow calls in an hour', () => {
  const eng = engine({ learnMs: 0, audit: true });
  const hits = listen(eng, 'suppression-abuse');
  eng.feed({ ts: 1_000, device: 'd', dst: 'a.example', bytes: 10 });
  for (let i = 0; i < 20; i += 1) eng.allow('d', 'dst', `name-${i}.example`);
  eng.feed({ ts: 2_000, device: 'd', dst: 'b.example', bytes: 10 });
  assert.equal(hits.length, 1);
  assert.equal(hits[0].device, '__engine__');
});

test('flow-shape-change fires when the first packets change under the same name', () => {
  const eng = engine({ learnMs: 5_000, flowShape: true });
  const hits = listen(eng, 'flow-shape-change');
  for (let i = 0; i < 25; i += 1) {
    eng.feed(flow({ ts: 1_000 + i, splt: { len: [64, 64, 64, 64], iat: [1, 1, 1, 1] } }));
  }
  for (let i = 0; i < 20; i += 1) {
    eng.feed(
      flow({ ts: 6_000 + i, splt: { len: [-1400, -1400, -1400, -1400], iat: [1, 1, 1, 1] } }),
    );
  }
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'high');
});

test('flow-shape-change fires when a camera TLS client is swapped under ECH', () => {
  const learnMs = 5_000;
  const eng = createEngine({
    shadow: true,
    flowShape: true,
    learnMs,
    tiers: ['T1', 'T3'],
  });
  eng.setDeviceClass('cam', 'camera');
  const hits = listen(eng, 'flow-shape-change');
  /** @type {any[]} */
  const fingerprints = [];
  const noteFingerprint = (row) => {
    if (row.detector === 'new-client-fingerprint') fingerprints.push(row);
  };
  eng.on('anomaly', noteFingerprint);
  eng.on('shadow-anomaly', noteFingerprint);
  const ja4 = 't13d1516h2_8daaf6152771_b0da82dd1658';
  const sni = 'update.vendor.com';
  const start = 1_000;
  for (let i = 0; i < 25; i += 1) {
    const ts = start + i;
    eng.feed({ type: 'tls', device: 'cam', ts, dstIp: '8.8.8.8', dstPort: 443, ja4, sni });
    eng.feed(
      flow({
        device: 'cam',
        ts,
        dstName: sni,
        splt: { len: [64, 64, 64, 64], iat: [1, 1, 1, 1] },
      }),
    );
  }
  for (let i = 0; i < 20; i += 1) {
    const ts = start + learnMs + i;
    eng.feed({ type: 'tls', device: 'cam', ts, dstIp: '8.8.8.8', dstPort: 443, ja4, sni });
    eng.feed(
      flow({
        device: 'cam',
        ts,
        dstName: sni,
        splt: { len: [-1400, -1400, -1400, -1400], iat: [1, 1, 1, 1] },
      }),
    );
  }
  assert.equal(hits.length, 1);
  assert.equal(hits[0].detector, 'flow-shape-change');
  assert.equal(hits[0].shadow, true);
  assert.equal(hits[0].severity, 'high');
  assert.equal(fingerprints.length, 0);
});

test('multivariate-outlier fires on three unusual windows', () => {
  const eng = engine({ learnMs: 40_000, windowMs: 1_000, outlier: true });
  eng.setDeviceClass('d', 'camera');
  const hits = listen(eng, 'multivariate-outlier');
  for (let w = 0; w < 30; w += 1) {
    eng.feed(
      flow({
        ts: w * 1_000,
        bytesOut: 20_000 + (w % 7) * 4_000,
        bytesIn: 10_000 + (w % 5) * 2_000,
        dstPort: 443,
      }),
    );
  }
  eng.lock('d');
  for (let w = 0; w < 3; w += 1) {
    eng.feed(
      flow({
        ts: 41_000 + w * 1_000,
        bytesOut: 1,
        bytesIn: 1,
        dstPort: 10_000 + w,
        dst: `odd-${w}.example.net`,
      }),
    );
  }
  eng.flush();
  assert.ok(hits.length >= 1);
});

test('sequence-surprise fires when the token order leaves the learned transitions', () => {
  const eng = engine({ learnMs: 20_000, windowMs: 1_000, sequence: true });
  const hits = listen(eng, 'sequence-surprise');
  for (let w = 0; w < 8; w += 1) {
    for (let i = 0; i < 21; i += 1) {
      eng.feed(flow({ ts: w * 1_000 + i, dstPort: 443, direction: 'out' }));
    }
  }
  eng.lock('d');
  for (let w = 0; w < 3; w += 1) {
    for (let i = 0; i < 21; i += 1) {
      eng.feed({
        type: 'app',
        device: 'd',
        ts: 30_000 + w * 1_000 + i,
        proto: 'mqtt',
        role: 'client',
        peerIp: '192.0.2.20',
        op: 'PUBLISH',
        target: `new-${i}.example.net`,
      });
    }
  }
  eng.flush();
  assert.ok(hits.length >= 1);
});

test('B22 shadow rows stay under medium on one 14-day benign pass per class', () => {
  const ids = [
    'dhcp-route-injection',
    'wpad-hijack',
    'ra-flood',
    'karma-responder',
    'cname-cloak',
    'ja4-churn',
    'dormant-reactivation',
    'firmware-size-divergence',
    'stun-turn-relay',
    'port-knock',
    'bacnet-bbmd-write',
    'modbus-unit-sweep',
    'mqtt-retained-command',
    'rtsp-new-viewer',
    'suppression-abuse',
    'multivariate-outlier',
    'sequence-surprise',
    'flow-shape-change',
  ];
  for (const profile of CLASS_NAMES) {
    const events = simulate({
      profile,
      days: 14,
      seed: 1,
      startTs: T0,
      rich: true,
      discovery: true,
      ipv6: true,
      wifi: true,
    });
    const eng = createEngine({
      shadow: true,
      learnMs: 7 * DAY,
      tiers: TIERS,
    });
    /** @type {string[]} */
    const bad = [];
    eng.on('shadow-anomaly', (row) => {
      if (!ids.includes(row.detector)) return;
      if (row.severity === 'medium' || row.severity === 'high' || row.severity === 'critical') {
        bad.push(row.detector);
      }
    });
    for (const event of events) eng.feed(event);
    eng.flush();
    assert.deepEqual(bad, [], profile);
  }
});
