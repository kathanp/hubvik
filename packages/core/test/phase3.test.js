'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const HOUR = 3600e3;

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1_000,
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

test('a plug that talks to too many registrable domains violates its class during learning', () => {
  const engine = createEngine({ learnMs: 86_400_000 });
  engine.setDeviceClass('d', 'plug');
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  for (let i = 0; i < 7; i++) {
    engine.feed({ device: 'd', dst: `shop${i}.example`, bytes: 10, ts: 1000 + i });
  }
  assert.ok(anomalies.some((item) => item.detector === 'class-violation' && item.hardRule));
  assert.ok(anomalies.some((item) => item.detector === 'supply-chain-suspect'));
});

test('consumer-site relay, chain RPC, and a direct IP', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T0', 'T1', 'T2'],
    lookup: (ip) =>
      ip === '1.2.3.4' ? { asn: 'AS999', country: 'ZZ' } : { asn: 'AS1', country: 'US' },
  });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  const names = [
    'www.amazon.com',
    'www.ebay.com',
    'www.facebook.com',
    'www.instagram.com',
    'www.ticketmaster.com',
    'www.stubhub.com',
  ];
  names.forEach((name, index) => {
    engine.feed(flow({ ts: 1000 + index, dstName: name, dstIp: `9.9.9.${index}` }));
  });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 2000,
    qname: 'eth.llamarpc.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  engine.feed(flow({ ts: 3000, dstIp: '8.8.8.8', dstName: undefined }));
  const ids = anomalies.map((item) => item.detector);
  assert.ok(ids.includes('proxy-relay'));
  assert.ok(ids.includes('blockchain-c2'));
  assert.ok(ids.includes('direct-ip'));
  assert.ok(ids.includes('new-asn'));
  assert.ok(ids.includes('new-country'));
});

test('mappings, tor, sweeps, and brute force', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T4'] });
  engine.loadIndicators([{ value: '203.0.113.50', type: 'tor', source: 'lab' }]);
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'mapping',
    device: 'd',
    ts: 1000,
    proto: 'upnp',
    port: 5555,
    externalPort: 5555,
  });
  engine.feed(flow({ ts: 1100, dstIp: '203.0.113.50' }));
  for (let i = 1; i <= 21; i++) {
    engine.feed(
      flow({ ts: 1200, proto: 'icmp', dstIp: `10.0.0.${i}`, direction: 'lan', srcIp: '10.0.0.8' }),
    );
  }
  for (let i = 0; i < 16; i++) {
    engine.feed(
      flow({
        ts: 1300,
        dstPort: 22,
        dstIp: `1.2.4.${i}`,
        durationMs: 20,
        bytesOut: 40,
        bytesIn: 0,
      }),
    );
  }
  for (let i = 0; i < 16; i++) {
    engine.feed(
      flow({
        ts: 1400,
        direction: 'in',
        dstPort: 22,
        srcIp: '198.51.100.9',
        dstIp: '10.0.0.8',
        durationMs: 20,
        bytesOut: 40,
        bytesIn: 0,
      }),
    );
  }
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'upnp-port-open',
    'tor-or-proxy',
    'lan-sweep',
    'brute-force-out',
    'brute-force-in',
  ]) {
    assert.ok(ids.has(id), id);
  }
});

test('slow upload, protocol mix, and connection churn', () => {
  const learned = createEngine({ learnMs: 10 * HOUR, tiers: ['T0', 'T1'], windowMs: 60_000 });
  for (let hour = 0; hour <= 6; hour++) {
    learned.feed(flow({ ts: hour * HOUR, bytesOut: 1000, pktsOut: 10, proto: 'tcp' }));
  }
  learned.lock('d');
  /** @type {any[]} */
  const anomalies = [];
  learned.on('anomaly', (item) => anomalies.push(item));
  learned.feed(flow({ ts: 7 * HOUR, bytesOut: 5_000_000, pktsOut: 10 }));
  assert.ok(anomalies.some((item) => item.detector === 'slow-exfil'));

  const mix = createEngine({ learnMs: 10 * HOUR, tiers: ['T0', 'T1'], windowMs: 60_000 });
  for (let i = 0; i < 25; i++)
    mix.feed(flow({ ts: 1000 + i, proto: 'tcp', pktsOut: 1, bytesOut: 100 }));
  mix.feed(flow({ ts: 120_000, proto: 'tcp', pktsOut: 1 }));
  mix.lock('d');
  /** @type {any[]} */
  const mixed = [];
  mix.on('anomaly', (item) => mixed.push(item));
  for (let i = 0; i < 25; i++) {
    mix.feed(flow({ ts: 240_000 + i, proto: 'udp', pktsOut: 1, bytesOut: 60 }));
  }
  mix.flush(300_000);
  assert.ok(mixed.some((item) => item.detector === 'protocol-mix-shift'));

  const churn = createEngine({ learnMs: 0, tiers: ['T0', 'T1'], windowMs: 60_000 });
  /** @type {any[]} */
  const rushed = [];
  churn.on('anomaly', (item) => rushed.push(item));
  for (let i = 0; i < 51; i++) churn.feed(flow({ ts: 1000 + i, dstIp: `1.2.8.${i % 20}` }));
  churn.flush(60_000);
  assert.ok(rushed.some((item) => item.detector === 'connection-churn'));
});

test('beacon, long session, dga, and dns tunnel', () => {
  const beacon = createEngine({ learnMs: 0, tiers: ['T0', 'T1'] });
  /** @type {any[]} */
  const periodic = [];
  beacon.on('anomaly', (item) => periodic.push(item));
  for (let i = 0; i < 20; i++) {
    beacon.feed(flow({ ts: 10_000 + i * 1000, dstIp: '198.51.100.20', bytesOut: 120, pktsOut: 1 }));
  }
  assert.ok(periodic.some((item) => item.detector === 'new-beacon'));

  const tunnel = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T2'] });
  /** @type {any[]} */
  const names = [];
  tunnel.on('anomaly', (item) => names.push(item));
  tunnel.feed(flow({ ts: 1000, durationMs: 700_000, dstIp: '198.51.100.21' }));
  for (let i = 0; i < 5; i++) {
    tunnel.feed({
      type: 'dns',
      device: 'd',
      ts: 2000,
      qname: `qxvzkplmnbw${i}.example`,
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
  }
  for (let i = 0; i < 11; i++) {
    tunnel.feed({
      type: 'dns',
      device: 'd',
      ts: 3000,
      qname: `${'qxvzkplmnbwr'.repeat(4)}${i}.example`,
      qtype: 'TXT',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
  }
  const ids = new Set(names.map((item) => item.detector));
  assert.ok(ids.has('long-connection'));
  assert.ok(ids.has('dga'));
  assert.ok(ids.has('dns-tunnel'));

  const learning = createEngine({ learnMs: 86_400_000, tiers: ['T0', 'T2'] });
  /** @type {any[]} */
  const early = [];
  learning.on('anomaly', (item) => early.push(item));
  for (let i = 0; i < 11; i++) {
    learning.feed({
      type: 'dns',
      device: 'd',
      ts: 3000,
      qname: `${'qxvzkplmnbwr'.repeat(4)}${i}.example`,
      qtype: 'TXT',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
  }
  assert.ok(early.some((item) => item.detector === 'dns-tunnel' && item.hardRule));
});

test('link layer, spoofing, zones, and tunnels', () => {
  const engine = createEngine({
    learnMs: 0,
    tiers: ['T0', 'T1', 'T2', 'T4', 'T5'],
    gatewayIp: '10.0.0.1',
    zones: [
      { id: 'iot', cidr: '10.1.0.0/16' },
      { id: 'lan', cidr: '10.2.0.0/16' },
    ],
  });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.feed({
    type: 'arp',
    device: 'aa',
    ts: 1000,
    ip: '10.0.0.1',
    mac: 'aa:aa:aa:aa:aa:01',
    op: 'reply',
  });
  engine.feed({
    type: 'arp',
    device: 'bb',
    ts: 1100,
    ip: '10.0.0.1',
    mac: 'bb:bb:bb:bb:bb:02',
    op: 'reply',
  });
  for (let i = 0; i < 31; i++) {
    engine.feed({
      type: 'arp',
      device: 'aa',
      ts: 1200,
      ip: '10.0.0.9',
      mac: 'aa:aa:aa:aa:aa:01',
      op: 'gratuitous',
    });
  }
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 1300,
    mac: 'aa',
    msg: 'ack',
    serverIp: '10.0.0.1',
    requestedIp: '10.0.0.8',
  });
  engine.feed({
    type: 'dhcp',
    device: 'd',
    ts: 1400,
    mac: 'aa',
    msg: 'offer',
    serverIp: '10.9.9.9',
    requestedIp: '10.0.0.8',
  });
  for (let i = 0; i < 21; i++) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 1500,
      mac: `02:00:00:00:00:${i.toString(16).padStart(2, '0')}`,
      msg: 'discover',
    });
  }
  engine.feed({
    type: 'ra',
    device: 'r',
    ts: 1600,
    srcMac: 'aa',
    srcIp: 'fe80::1',
    prefixes: [],
    routerLifetime: 1800,
  });
  engine.feed({
    type: 'ra',
    device: 'r',
    ts: 1700,
    srcMac: 'bb',
    srcIp: 'fe80::2',
    prefixes: [],
    routerLifetime: 1800,
  });
  engine.feed(flow({ ts: 1800, srcIp: '192.0.2.9' }));
  engine.feed(flow({ ts: 1900, proto: 'icmp', icmpType: 5, srcIp: '10.0.0.50', direction: 'lan' }));
  engine.feed(flow({ ts: 2000, direction: 'lan', srcIp: '10.1.0.8', dstIp: '10.2.0.9' }));
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 2100,
    qname: 'host.ngrok.io',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  engine.feed(flow({ ts: 2200, proto: 'udp', dstPort: 51820, bytesOut: 148 }));
  engine.feed(flow({ ts: 2300, proto: 'icmp', bytesOut: 1000, pktsOut: 1, icmpType: 8 }));
  engine.feed(flow({ ts: 2400, proto: 41 }));
  engine.feed(flow({ ts: 2500, proto: 'udp', dstPort: 123, dstIp: '9.9.9.9' }));
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'arp-spoof',
    'gratuitous-arp-flood',
    'rogue-dhcp',
    'dhcp-starvation',
    'rogue-ra',
    'src-spoof',
    'icmp-redirect',
    'zone-violation',
    'tunnel-service',
    'vpn-protocol',
    'icmp-tunnel',
    'ipv6-tunnel',
    'ntp-rogue',
  ]) {
    assert.ok(ids.has(id), id);
  }
});

test('media, mining, OT, cleartext downloads, and a drift incident', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0', 'T1', 'T5'] });
  /** @type {any[]} */
  const anomalies = [];
  /** @type {any[]} */
  const incidents = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  engine.on('incident', (item) => incidents.push(item));
  engine.feed(flow({ ts: 1000, dstPort: 554, dstIp: '198.51.100.40' }));
  engine.feed({
    type: 'app',
    device: 'd',
    ts: 1100,
    proto: 'stratum',
    role: 'client',
    peerIp: '198.51.100.41',
    op: 'mining.subscribe',
  });
  engine.feed(flow({ ts: 1200, dstPort: 502, dstIp: '1.2.3.50', proto: 'tcp' }));
  engine.feed(
    flow({
      ts: 1300,
      direction: 'in',
      dstPort: 80,
      srcPort: 80,
      bytesIn: 6_000_000,
      srcIp: '198.51.100.43',
    }),
  );
  engine.feed(flow({ ts: 1400, dstPort: 23, proto: 'tcp' }));
  engine.feed({ device: 'd', dst: 'one.example', bytes: 10, ts: 1500 });
  engine.feed({ device: 'd', dst: 'two.example', bytes: 10, ts: 1600 });
  engine.feed({ device: 'd', dst: 'three.example', bytes: 10, ts: 1700 });
  const ids = new Set(anomalies.map((item) => item.detector));
  for (const id of [
    'stream-to-new-destination',
    'cryptomining',
    'ot-wan-exposure',
    'update-over-cleartext',
    'update-from-new-source',
    'posture-cleartext-auth',
    'post-update-drift',
  ]) {
    assert.ok(ids.has(id), id);
  }
  assert.ok(incidents.some((item) => item.stages.length >= 2 || item.score >= 70));

  const quiet = createEngine({ learnMs: 0 });
  /** @type {any[]} */
  const one = [];
  /** @type {any} */
  let rolled = null;
  quiet.on('anomaly', (item) => one.push(item));
  quiet.on('incident', (item) => {
    rolled = item;
  });
  quiet.feed({ device: 'd', dst: 'only.example', bytes: 1, ts: 1000 });
  const before = rolled.score;
  quiet.ack(one[0].id);
  assert.ok(rolled.score < before);
});

test('a learned UPnP mapping does not fire, and a new one does', () => {
  const engine = createEngine({ learnMs: 10_000, tiers: ['T0', 'T1'] });
  engine.feed({
    type: 'mapping',
    device: 'd',
    ts: 1000,
    proto: 'upnp',
    port: 80,
    externalPort: 8080,
  });
  engine.lock('d');
  /** @type {any[]} */
  const found = [];
  engine.on('anomaly', (row) => {
    if (row.detector === 'upnp-port-open') found.push(row);
  });
  engine.feed({
    type: 'mapping',
    device: 'd',
    ts: 20_000,
    proto: 'upnp',
    port: 80,
    externalPort: 8080,
  });
  engine.feed({
    type: 'mapping',
    device: 'd',
    ts: 21_000,
    proto: 'upnp',
    port: 81,
  });
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].actual, 'upnp:81');
});
