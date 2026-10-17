'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    ...extra,
  };
}

/**
 * @param {Record<string, unknown>} [extra]
 */
function tls(extra = {}) {
  return {
    type: 'tls',
    device: 'd',
    ts: 1000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    sni: 'video.vendor.com',
    ja4: 't13d1516h2_8daaf6152771_b186095e22b6',
    version: 'TLSv1.3',
    cert: { issuer: 'Vendor CA', selfSigned: false, notAfter: 2_000_000_000_000 },
    ...extra,
  };
}

test('TLS metadata: new fingerprint, issuer change, missing SNI, odd port, downgrade', () => {
  const learned = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T1', 'T3'] });
  learned.feed(tls({ ts: 1000 }));
  learned.feed(tls({ ts: 1100, dstPort: 443 }));
  learned.lock('d');
  /** @type {any[]} */
  const anomalies = [];
  learned.on('anomaly', (item) => anomalies.push(item));
  learned.feed(tls({ ts: 2000, ja4: 't13d9999h2_aaaaaaaaaaaa_bbbbbbbbbbbb' }));
  learned.feed(tls({ ts: 2100, cert: { issuer: 'Evil CA' } }));
  learned.feed(
    tls({ ts: 2200, sni: undefined, dstIp: '198.51.100.8', ja4: undefined, cert: undefined }),
  );
  learned.feed(tls({ ts: 2300, dstPort: 8443 }));
  learned.feed({
    type: 'http',
    device: 'd',
    ts: 2400,
    dstIp: '1.2.3.4',
    dstPort: 80,
    method: 'GET',
    host: 'video.vendor.com',
  });
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'new-client-fingerprint',
    'cert-change',
    'sni-missing',
    'tls-on-odd-port',
    'cleartext-regression',
  ]) {
    assert.ok(ids.has(id), id);
  }
});

test('browser fingerprint, weak TLS, backconnect, LAN follow, and P2P', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T0', 'T1', 'T3'],
    browserJa4: ['t13dbrowser_ja4'],
  });
  engine.setDeviceClass('d', 'camera');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed(tls({ ts: 1000, ja4: 't13dbrowser_ja4' }));
  engine.feed(tls({ ts: 1100, version: 'TLSv1.0', ja4: 'other', dstIp: '1.2.3.5' }));
  engine.feed(flow({ ts: 2000, durationMs: 120_000, dstIp: '9.9.9.9' }));
  for (let i = 0; i < 8; i++) {
    engine.feed(flow({ ts: 2500 + i, durationMs: 100, dstIp: `9.9.8.${i}` }));
  }
  engine.feed(
    flow({ ts: 4000, direction: 'in', bytesIn: 500, srcIp: '203.0.113.9', dstIp: '10.0.0.8' }),
  );
  engine.feed(flow({ ts: 4500, direction: 'lan', dstIp: '10.0.0.20', srcIp: '10.0.0.8' }));
  for (let i = 0; i < 30; i++) {
    engine.feed(
      flow({
        ts: 5000,
        dstPort: 40000,
        direction: i < 15 ? 'in' : 'out',
        srcIp: `198.51.100.${i + 1}`,
        dstIp: `203.0.113.${(i % 20) + 1}`,
      }),
    );
  }
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'browser-mimic',
    'posture-weak-tls',
    'proxy-backconnect',
    'lan-via-proxy',
    'p2p-pattern',
  ]) {
    assert.ok(ids.has(id), id);
  }
});

test('stuffing, ads, QUIC, beacon change, answer drift, and fast flux', () => {
  const engine = createEngine({
    learnMs: 86_400_000,
    tiers: ['T0', 'T1', 'T2'],
    lookup: (ip) => ({ asn: ip === '1.1.1.1' ? 'AS1' : 'AS2', country: 'US' }),
  });
  engine.loadIndicators([
    { value: 'doubleclick.net', type: 'ad', source: 'lab' },
    { value: 'ads.example', type: 'ad', source: 'lab' },
  ]);
  for (let i = 0; i < 9; i++) engine.feed(flow({ ts: i * 1000, dstIp: '1.2.3.9', bytesOut: 80 }));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1000,
    qname: 'video.vendor.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '1.1.1.1', ttl: 300 }],
  });
  engine.lock('d');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  for (let i = 0; i < 8; i++)
    engine.feed(flow({ ts: 100_000 + i * 10_000, dstIp: '1.2.3.9', bytesOut: 80 }));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 200_000,
    qname: 'video.vendor.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers: [{ type: 'A', value: '8.8.8.8', ttl: 300 }],
  });
  const answers = [];
  for (let i = 1; i <= 8; i++) answers.push({ type: 'A', value: `203.0.113.${i}`, ttl: 5 });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 210_000,
    qname: 'flux.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
    answers,
  });
  for (let i = 0; i < 5; i++) {
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 220_000,
      qname: `${i}.doubleclick.net`,
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
  }
  for (let i = 0; i < 15; i++) {
    engine.feed(tlsLike(230_000, `login${i}.example`));
  }
  engine.feed(flow({ ts: 240_000, proto: 'udp', dstPort: 443, dstIp: '9.9.9.1' }));
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'beacon-change',
    'answer-drift',
    'fast-flux',
    'ad-fraud',
    'credential-stuffing-out',
    'quic-new',
  ]) {
    assert.ok(ids.has(id), id);
  }
});

test('building protocols and MQTT topics', () => {
  const engine = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T5'] });
  engine.feed(app('ahu', 1000, '10.0.0.2', 'bacnet', 'WriteProperty', 'fan', 1));
  engine.feed(app('ahu', 1100, '10.0.0.2', 'bacnet', 'I-Am', 'device-7'));
  engine.feed(app('cam', 1200, '10.0.0.3', 'mqtt', 'PUBLISH', 'home/status'));
  engine.lock('ahu');
  engine.lock('cam');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed(app('ahu', 2000, '10.0.0.2', 'bacnet', 'WriteProperty', 'damper', 1));
  for (let i = 0; i < 11; i++) {
    engine.feed(app('ahu', 3000 + i, `10.1.0.${i}`, 'bacnet', 'Who-Is', `n${i}`));
    engine.feed(app('ahu', 4000, '10.0.0.2', 'bacnet', 'ReadProperty', 'x', undefined, 'error'));
  }
  engine.feed(app('ahu', 5000, '10.0.0.9', 'bacnet', 'I-Am', 'device-7'));
  for (let i = 0; i < 12; i++) {
    engine.feed(app('ahu', 6000 + i, '10.0.0.2', 'bacnet', 'WriteProperty', 'fan', 1));
  }
  engine.flush(120_000);
  engine.feed(app('cam', 7000, '10.0.0.3', 'mqtt', 'SUBSCRIBE', '#'));
  engine.feed(app('cam', 7100, '10.0.0.3', 'mqtt', 'PUBLISH', 'cmd/reboot'));
  for (let i = 0; i < 31; i++) {
    engine.feed(app('cam', 8000, '10.0.0.3', 'mqtt', 'PUBLISH', 'home/status'));
  }
  engine.feed(app('cam', 9000, '10.0.0.4', 'onvif', 'SetUser', 'admin'));
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'ot-write-new',
    'ot-recon',
    'ot-spoof',
    'ot-error-burst',
    'ot-write-rate',
    'mqtt-wildcard-subscribe',
    'mqtt-topic-new',
    'mqtt-publish-rate',
    'onvif-config-change',
  ]) {
    assert.ok(ids.has(id), id);
  }
});

test('fleet wave and peer divergence', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  for (let i = 0; i < 3; i++) {
    engine.feed({ device: `cam-${i}`, dst: 'wave.example', bytes: 10, ts: 1000 + i });
  }
  assert.ok(anomalies.some((item) => item.detector === 'fleet-wave'));

  const peers = createEngine({ learnMs: 86_400_000 });
  for (let i = 0; i < 5; i++) {
    peers.setPeerGroup(`p${i}`, 'cams');
    peers.feed({ device: `p${i}`, dst: 'video.vendor.com', bytes: 10, ts: 1000 });
  }
  peers.setPeerGroup('odd', 'cams');
  peers.feed({ device: 'odd', dst: 'video.vendor.com', bytes: 10, ts: 1000 });
  peers.lock('odd');
  /** @type {any[]} */
  const odd = [];
  peers.on('anomaly', (item) => odd.push(item));
  peers.feed({ device: 'odd', dst: 'evil.example', bytes: 10, ts: 2000 });
  assert.ok(odd.some((item) => item.detector === 'peer-divergence'));
});

/**
 * @param {number} ts
 * @param {string} sni
 */
/**
 * @param {string} device
 * @param {number} ts
 * @param {string} peer
 * @param {string} proto
 * @param {string} op
 * @param {string} target
 * @param {number | string} [value]
 * @param {string} [result]
 */
function app(device, ts, peer, proto, op, target, value, result) {
  return {
    type: 'app',
    device,
    ts,
    proto,
    role: 'server',
    peerIp: peer,
    op,
    target,
    value,
    result: result || 'ok',
  };
}

function tlsLike(ts, sni) {
  return {
    type: 'flow',
    device: 'd',
    ts,
    srcIp: '10.0.0.8',
    srcPort: 41000,
    dstIp: '1.2.3.40',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 400,
    bytesIn: 400,
    pktsOut: 4,
    pktsIn: 4,
    durationMs: 200,
    dstName: sni,
  };
}
