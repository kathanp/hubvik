'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine, detectors } = require('../src/index.js');

const DAY = 24 * 3600e3;
const NUMERIC = new Set(['gt', 'gte', 'lt']);

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 0,
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
 * Crafted attacks copied from the detector tests and phase replays.
 * @type {Record<string, (engine: any) => void>}
 */
const ATTACKS = {
  'src-spoof'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 0,
      mac: 'aa',
      msg: 'ack',
      serverIp: '10.0.0.1',
      requestedIp: '10.0.0.8',
    });
    engine.feed(flow({ ts: 1000, srcIp: '192.0.2.9' }));
  },
  'tftp-activity'(engine) {
    engine.feed(flow({ ts: 500, proto: 'udp', dstPort: 69, direction: 'out' }));
  },
  'spam-relay'(engine) {
    for (let i = 0; i < 11; i++) engine.feed(flow({ ts: 600 + i, dstPort: 25 }));
  },
  'rogue-dhcp'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 0,
      mac: 'aa',
      msg: 'ack',
      serverIp: '10.0.0.1',
    });
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 1000,
      mac: 'aa',
      msg: 'offer',
      serverIp: '10.9.9.9',
    });
  },
  'rogue-ra'(engine) {
    engine.feed({
      type: 'ra',
      device: 'r',
      ts: 0,
      srcMac: 'aa',
      srcIp: 'fe80::1',
      prefixes: [],
      routerLifetime: 1800,
    });
    engine.feed({
      type: 'ra',
      device: 'r',
      ts: 1000,
      srcMac: 'bb',
      srcIp: 'fe80::2',
      prefixes: [],
      routerLifetime: 1800,
    });
  },
  'new-device'(engine) {
    engine.feed({ device: 'first', dst: 'a.example', bytes: 1, ts: 0 });
    engine.feed({ device: 'other', dst: 'a.example', bytes: 1, ts: 5000 });
  },
  'clock-jump'(engine) {
    engine.feed(flow({ ts: 100000 }));
    engine.feed(flow({ ts: 0 }));
  },
  'alert-storm'(engine) {
    engine.feed(flow({ ts: 0, dstIp: '1.2.3.4' }));
    engine.feed(flow({ ts: 1000, dstIp: '1.2.3.5' }));
  },
  'policy-violation'(engine) {
    engine.feed(flow({ ts: 0, dstPort: 23 }));
  },
  'threat-intel-match'(engine) {
    engine.loadIndicators([
      { value: 'evil.example', type: 'domain', source: 'lab', confidence: 0.7 },
    ]);
    engine.feed({ device: 'd', dst: 'a.evil.example', bytes: 1, ts: 100 });
  },
  'adb-exposure'(engine) {
    engine.feed(
      flow({ ts: 1000, direction: 'lan', srcIp: '10.0.0.9', dstIp: '10.0.0.8', dstPort: 5555 }),
    );
  },
  'inbound-from-wan'(engine) {
    engine.feed(
      flow({ ts: 0, direction: 'in', srcIp: '1.2.3.50', dstPort: 23, dstIp: '10.0.0.8' }),
    );
  },
  'icmp-redirect'(engine) {
    engine.feed(
      flow({ ts: 1900, proto: 'icmp', icmpType: 5, srcIp: '10.0.0.50', direction: 'lan' }),
    );
  },
  'tor-or-proxy'(engine) {
    engine.loadIndicators([{ value: '203.0.113.50', type: 'tor', source: 'lab' }]);
    engine.feed(flow({ ts: 1100, dstIp: '203.0.113.50' }));
  },
  cryptomining(engine) {
    engine.feed({
      type: 'app',
      device: 'd',
      ts: 1100,
      proto: 'stratum',
      role: 'client',
      peerIp: '198.51.100.41',
      op: 'mining.subscribe',
    });
  },
  'horizontal-scan'(engine) {
    for (let i = 1; i <= 12; i++) {
      engine.feed(flow({ ts: 1000 + i, dstIp: `1.2.3.${i}`, dstPort: 23 }));
    }
  },
  'packet-flood'(engine) {
    engine.feed(flow({ ts: 0, pktsOut: 800, pktsIn: 0, bytesOut: 8000, bytesIn: 0 }));
  },
  'egress-flood'(engine) {
    engine.feed(
      flow({
        ts: 0,
        proto: 'udp',
        dstPort: 5004,
        dstIp: '8.8.8.8',
        bytesOut: 60000 * 1400,
        bytesIn: 0,
        pktsOut: 60000,
      }),
    );
  },
  'dns-tunnel'(engine) {
    for (let i = 0; i < 11; i++) {
      engine.feed({
        type: 'dns',
        device: 'd',
        ts: 3000,
        qname: `${'qxvzkplmnbwr'.repeat(4)}${i}.example`,
        qtype: 'TXT',
        rcode: 'NOERROR',
        resolver: '10.0.0.1',
      });
    }
  },
  'brute-force-out'(engine) {
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
  },
  'coap-amplification'(engine) {
    engine.feed(
      flow({
        ts: 2000,
        proto: 'udp',
        direction: 'out',
        srcPort: 5683,
        dstPort: 9999,
        dstIp: '1.2.3.10',
        bytesOut: 2000,
        bytesIn: 0,
      }),
    );
  },
  'reflection-participation'(engine) {
    engine.feed(
      flow({
        ts: 1000,
        proto: 'udp',
        direction: 'out',
        srcPort: 1900,
        dstPort: 80,
        dstIp: '1.2.3.9',
        bytesOut: 2000,
        bytesIn: 100,
      }),
    );
  },
  'class-violation'(engine) {
    engine.setDeviceClass('d', 'plug');
    for (let i = 0; i < 7; i++) {
      engine.feed({ device: 'd', dst: `shop${i}.example`, bytes: 10, ts: 1000 + i });
    }
  },
  'proxy-relay'(engine) {
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
  },
  'proxy-sdk-traffic'(engine) {
    engine.setDeviceClass('cam', 'camera');
    engine.loadIndicators([
      { value: 'sdk.proxy.example', type: 'proxy-sdk', source: 'lab', confidence: 0.9 },
    ]);
    engine.feed({
      type: 'tls',
      device: 'cam',
      ts: 0,
      dstIp: '1.2.3.4',
      dstPort: 443,
      sni: 'cdn.sdk.proxy.example',
    });
  },
  'ot-wan-exposure'(engine) {
    engine.feed(flow({ ts: 1200, dstPort: 502, dstIp: '1.2.3.50', proto: 'tcp' }));
  },
  'ot-dangerous-op'(engine) {
    engine.feed({
      type: 'app',
      device: 'd',
      ts: 1000,
      proto: 'bacnet',
      role: 'client',
      peerIp: '10.0.0.2',
      op: 'STOP',
    });
  },
  'onvif-config-change'(engine) {
    engine.feed({
      type: 'app',
      device: 'cam',
      ts: 9000,
      proto: 'onvif',
      role: 'client',
      peerIp: '10.0.0.4',
      op: 'SetUser',
    });
  },
  'post-update-drift'(engine) {
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
        bytesIn: 6000000,
        srcIp: '198.51.100.43',
      }),
    );
    engine.feed(flow({ ts: 1400, dstPort: 23, proto: 'tcp' }));
    engine.feed({ device: 'd', dst: 'one.example', bytes: 10, ts: 1500 });
    engine.feed({ device: 'd', dst: 'two.example', bytes: 10, ts: 1600 });
    engine.feed({ device: 'd', dst: 'three.example', bytes: 10, ts: 1700 });
  },
  'supply-chain-suspect'(engine) {
    engine.setDeviceClass('d', 'plug');
    for (let i = 0; i < 7; i++) {
      engine.feed({ device: 'd', dst: `shop${i}.example`, bytes: 10, ts: 1000 + i });
    }
  },
  'arp-spoof'(engine) {
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
  },
  'blockchain-c2'(engine) {
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 2000,
      qname: 'eth.llamarpc.com',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
  },
  'state-cap'(engine) {
    engine.feed({ device: 'a', dst: 'a.example', bytes: 1, ts: 1 });
    engine.feed({ device: 'b', dst: 'b.example', bytes: 1, ts: 2 });
  },
  'tier-silent'(engine) {
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 0,
      qname: 'video.vendor.com',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
    for (let hour = 0; hour <= 6; hour++) {
      engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 10, ts: hour * 3600e3 });
      engine.feed(flow({ ts: hour * 3600e3 }));
    }
    engine.tick(6 * 3600e3);
  },
  'input-gap'(engine) {
    engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
    engine.tick(25 * 3600e3);
  },
  'new-beacon'(engine) {
    for (let i = 0; i < 20; i++) {
      engine.feed(
        flow({ ts: 10000 + i * 1000, dstIp: '198.51.100.20', bytesOut: 120, pktsOut: 1 }),
      );
    }
  },
  'protocol-mix-shift'(engine) {
    for (let i = 0; i < 25; i++) {
      engine.feed(flow({ ts: 1000 + i, proto: 'tcp', pktsOut: 1, bytesOut: 100 }));
    }
    engine.feed(flow({ ts: 120000, proto: 'tcp', pktsOut: 1 }));
    engine.lock('d');
    for (let i = 0; i < 25; i++) {
      engine.feed(flow({ ts: 240000 + i, proto: 'udp', pktsOut: 1, bytesOut: 60 }));
    }
    engine.flush(300000);
  },
  'beacon-change'(engine) {
    for (let i = 0; i < 9; i++) engine.feed(flow({ ts: i * 1000, dstIp: '1.2.3.9', bytesOut: 80 }));
    engine.lock('d');
    for (let i = 0; i < 8; i++) {
      engine.feed(flow({ ts: 100000 + i * 10000, dstIp: '1.2.3.9', bytesOut: 80 }));
    }
  },
  'new-protocol'(engine) {
    engine.feed(flow({ ts: 0 }));
    engine.lock('d');
    engine.feed(flow({ ts: 180000, proto: 'gre' }));
  },
  'young-domain'(engine) {
    engine.loadIndicators([
      { value: 'fresh.example', type: 'young-domain', source: 'lab', confidence: 0.8 },
    ]);
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 1000,
      qname: 'fresh.example',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '192.0.2.1',
    });
  },
  'ttl-anomaly'(engine) {
    for (let i = 0; i < 20; i++) engine.feed(flow({ ts: i * 1000, ttl: 64 }));
    engine.lock('d');
    engine.feed(flow({ ts: 200000, ttl: 128 }));
  },
  'exploit-probe-http'(engine) {
    engine.feed({
      type: 'http',
      device: 'd',
      ts: 0,
      dstIp: '10.0.0.8',
      dstPort: 80,
      method: 'GET',
      path: '/shell?',
      direction: 'in',
    });
  },
  'slow-scan'(engine) {
    for (let i = 0; i < 50; i += 1) {
      engine.feed(flow({ ts: i * 1000, dstIp: `9.9.0.${(i % 200) + 1}`, dstPort: 8000 + i }));
    }
  },
  'jitter-beacon'(engine) {
    for (let i = 0; i < 30; i += 1) {
      engine.feed(flow({ ts: i * 300000, dstIp: '9.9.9.9', bytesOut: 120 }));
    }
  },
  'multi-horizon-exfil'(engine) {
    for (let hour = 0; hour < 6; hour += 1)
      engine.feed(flow({ ts: hour * 3600e3, bytesOut: 1000 }));
    engine.feed(flow({ ts: 6 * 3600e3, bytesOut: 2_000_000 }));
  },
  'graph-new-bridge'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'aa:bb:cc:dd:ee:01',
      ts: 1,
      mac: 'aa:bb:cc:dd:ee:01',
      msg: 'ack',
      requestedIp: '10.1.0.2',
    });
    engine.feed({
      type: 'dhcp',
      device: 'aa:bb:cc:dd:ee:02',
      ts: 2,
      mac: 'aa:bb:cc:dd:ee:02',
      msg: 'ack',
      requestedIp: '10.2.0.2',
    });
    engine.feed(
      flow({ ts: 1000, device: 'src', direction: 'lan', dstIp: '10.1.0.2', dstPort: 80 }),
    );
    engine.feed(
      flow({ ts: 2000, device: 'src', direction: 'lan', dstIp: '10.2.0.2', dstPort: 80 }),
    );
  },
  'exploit-then-download'(engine) {
    engine.feed(
      flow({
        ts: 1000,
        direction: 'in',
        srcIp: '1.2.3.4',
        srcPort: 443,
        dstIp: '10.0.0.5',
        dstPort: 80,
      }),
    );
    engine.feed(
      flow({
        ts: 2000,
        direction: 'out',
        dstIp: '9.9.9.9',
        dstPort: 443,
        bytesIn: 200000,
      }),
    );
  },
  'ssh-brute-then-session'(engine) {
    for (let i = 0; i < 10; i += 1) {
      engine.feed(
        flow({
          ts: 1000 + i,
          direction: 'in',
          srcIp: '1.2.3.4',
          srcPort: 40000,
          dstIp: '10.0.0.5',
          dstPort: 22,
          durationMs: 200,
        }),
      );
    }
    engine.feed(
      flow({
        ts: 2000,
        direction: 'in',
        srcIp: '1.2.3.4',
        srcPort: 40000,
        dstIp: '10.0.0.5',
        dstPort: 22,
        durationMs: 60000,
      }),
    );
  },
  'cloud-storage-exfil'(engine) {
    engine.feed(
      flow({
        ts: 1000,
        dstName: 'bucket.s3.amazonaws.com',
        dstIp: '1.2.3.4',
        bytesOut: 11 * 1024 * 1024,
      }),
    );
  },
  'nd-spoof'(engine) {
    engine.feed({
      type: 'nd',
      device: 'cam-1',
      ts: 1000,
      op: 'na',
      ip: '2001:db8::1',
      mac: 'aa:bb:cc:dd:ee:01',
      router: true,
    });
    engine.feed({
      type: 'nd',
      device: 'cam-1',
      ts: 2000,
      op: 'na',
      ip: '2001:db8::1',
      mac: 'aa:bb:cc:dd:ee:02',
      router: true,
    });
  },
  'dhcpv6-rogue'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'cam-1',
      ts: 1000,
      mac: 'aa:bb:cc:dd:ee:01',
      msg: 'offer',
      v6: true,
      serverIp: '2001:db8::1',
    });
    engine.feed({
      type: 'dhcp',
      device: 'cam-1',
      ts: 6000,
      mac: 'aa:bb:cc:dd:ee:01',
      msg: 'offer',
      v6: true,
      serverIp: '2001:db8::9',
    });
  },
  'wifi-deauth-flood'(engine) {
    for (let i = 0; i < 30; i += 1) {
      engine.feed({
        type: 'wifi',
        device: 'cam-1',
        ts: 1000 + i,
        mac: 'aa:bb:cc:dd:ee:01',
        op: 'deauth',
      });
    }
  },
  'evil-twin'(engine) {
    engine.feed({
      type: 'wifi',
      device: 'cam-1',
      ts: 1000,
      mac: 'aa:bb:cc:dd:ee:01',
      bssid: 'aa:bb:cc:dd:ee:f0',
      ssid: 'home',
      op: 'assoc',
    });
    engine.feed({
      type: 'wifi',
      device: 'cam-1',
      ts: 6000,
      mac: 'aa:bb:cc:dd:ee:01',
      bssid: 'aa:bb:cc:dd:ee:f9',
      ssid: 'home',
      op: 'assoc',
    });
  },
  'upnp-callstranger'(engine) {
    engine.feed({
      type: 'app',
      device: 'cam-1',
      ts: 1000,
      proto: 'upnp',
      role: 'server',
      peerIp: '10.0.0.50',
      op: 'SUBSCRIBE',
      target: 'http://1.2.3.4/callback',
    });
  },
  'matter-new-controller'(engine) {
    engine.feed({
      type: 'app',
      device: 'cam-1',
      ts: 1000,
      proto: 'matter',
      role: 'server',
      peerIp: '10.0.0.2',
      op: 'AddNOC',
    });
    engine.feed({
      type: 'app',
      device: 'cam-1',
      ts: 6000,
      proto: 'matter',
      role: 'server',
      peerIp: '10.0.0.9',
      op: 'AddNOC',
    });
  },
  'graph-role-change'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'aa:bb:cc:dd:ee:10',
      ts: 1,
      mac: 'aa:bb:cc:dd:ee:10',
      msg: 'ack',
      requestedIp: '10.0.0.10',
    });
    for (let i = 0; i < 5; i += 1) {
      engine.feed(
        flow({
          ts: 1000 + i,
          device: `peer-${i}`,
          direction: 'lan',
          dstIp: '10.0.0.10',
          dstPort: 80,
        }),
      );
    }
    engine.flush(60_000);
  },
  'dispersed-flood'(engine) {
    for (let i = 1; i <= 8; i += 1) {
      engine.feed(
        flow({
          ts: 1000,
          dstIp: `9.9.9.${i}`,
          bytesOut: 1000,
          bytesIn: 0,
          pktsOut: 1000,
          pktsIn: 0,
        }),
      );
    }
  },
  'txt-channel'(engine) {
    const label = 'a'.repeat(20);
    for (let i = 0; i < 12; i += 1) {
      engine.feed({
        type: 'dns',
        device: 'd',
        ts: 1000 + i,
        qname: `${label}.example`,
        qtype: 'TXT',
        rcode: 'NOERROR',
        resolver: '10.0.0.1',
      });
    }
  },
  'inbound-lateral'(engine) {
    engine.feed(
      flow({
        ts: 0,
        direction: 'in',
        srcIp: '8.8.8.8',
        dstIp: '10.0.0.8',
        dstPort: 554,
        tcpOutcome: 'established',
      }),
    );
    for (let i = 2; i <= 4; i += 1) {
      engine.feed(
        flow({
          ts: 1000,
          direction: 'lan',
          dstIp: `10.0.0.${i}`,
          tcpOutcome: 'established',
        }),
      );
    }
  },
  'short-lived-cert'(engine) {
    engine.feed({
      type: 'tls',
      device: 'd',
      ts: 1000,
      dstIp: '9.9.9.9',
      dstPort: 443,
      sni: 'c2.example',
      cert: { sha256: 'abc123', notBefore: 0, notAfter: 172800000 },
    });
  },
  'h2-fanout'(engine) {
    for (let i = 1; i <= 64; i += 1) {
      engine.feed({
        type: 'tls',
        device: 'd',
        ts: 1000,
        dstIp: `9.9.0.${i}`,
        dstPort: 443,
        alpn: ['h2'],
      });
    }
  },
  'onion-name'(engine) {
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 1000,
      qname: 'hidden.onion',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
    });
  },
  'proxy-fanin'(engine) {
    for (let i = 1; i <= 8; i += 1) {
      engine.feed(
        flow({
          ts: 1000,
          direction: 'in',
          srcIp: `8.8.8.${i}`,
          dstIp: '10.0.0.8',
          dstPort: 1080,
          proto: 'tcp',
          tcpOutcome: 'established',
          bytesOut: 200,
          bytesIn: 800,
        }),
      );
    }
  },
  'scatter-udp'(engine) {
    for (let i = 1; i <= 40; i += 1) {
      engine.feed(
        flow({
          ts: 1000,
          dstIp: `9.9.1.${i}`,
          dstPort: 27015,
          proto: 'udp',
          bytesOut: 1000,
          bytesIn: 0,
          pktsOut: 20,
          pktsIn: 0,
        }),
      );
    }
  },
};

/**
 * @param {string} id
 */
const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

function optionsFor(id) {
  /** @type {any} */
  const options = { tiers: TIERS, learnMs: 0, shadow: true };
  if (id === 'alert-storm') options.detectors = { 'alert-storm': { maxPerMinute: 1 } };
  if (id === 'new-device' || id === 'spam-relay') options.learnMs = 1000;
  if (id === 'clock-jump') options.learnMs = 86400000;
  if (
    id === 'horizontal-scan' ||
    id === 'dns-tunnel' ||
    id === 'class-violation' ||
    id === 'supply-chain-suspect'
  ) {
    options.learnMs = 86400000;
  }
  if (id === 'state-cap') options.maxDevices = 1;
  if (id === 'tier-silent') options.tiers = ['T0', 'T1', 'T2'];
  if (id === 'protocol-mix-shift') {
    options.learnMs = 10 * 3600e3;
    options.windowMs = 60000;
  }
  if (id === 'beacon-change') options.learnMs = 86400000;
  if (id === 'ttl-anomaly') options.learnMs = 100000;
  if (id === 'multi-horizon-exfil') options.learnMs = 6 * 3600e3;
  if (id === 'graph-new-bridge') {
    options.identity = 'auto';
    options.zones = [
      { id: 'a', cidr: '10.1.0.0/16' },
      { id: 'b', cidr: '10.2.0.0/16' },
    ];
  }
  if (id === 'graph-role-change') options.identity = 'auto';
  if (id === 'evil-twin' || id === 'matter-new-controller' || id === 'dhcpv6-rogue') {
    options.learnMs = 5000;
  }
  if (id === 'policy-violation') {
    options.policy = [{ id: 'no-telnet', severity: 'high', match: { direction: 'out', port: 23 } }];
  }
  return options;
}

test('every explaining detector meets the explain contract', () => {
  const covered = Object.values(detectors).filter((det) => det.meta && det.meta.explains === true);
  assert.ok(covered.length > 0);
  for (const det of covered) {
    const fire = ATTACKS[det.id];
    assert.ok(fire, `${det.id} has no crafted attack`);
    const engine = createEngine(optionsFor(det.id));
    /** @type {any[]} */
    const hits = [];
    engine.on('anomaly', (item) => {
      if (item.detector === det.id) hits.push(item);
    });
    engine.on('shadow-anomaly', (item) => {
      if (item.detector === det.id) hits.push(item);
    });
    fire(engine);
    assert.ok(hits.length >= 1, `${det.id} did not fire`);
    const anomaly = hits[0];
    const row = engine.explain(anomaly.id);
    assert.ok(row, `${det.id} explain`);
    assert.ok(row.test, `${det.id} test`);
    assert.ok(row.observed !== undefined && row.observed !== null, `${det.id} observed`);
    assert.ok(
      row.threshold !== undefined || row.learned !== undefined,
      `${det.id} threshold or learned`,
    );
    if (NUMERIC.has(row.test)) {
      assert.strictEqual(row.margin, row.observed / row.threshold, `${det.id} margin`);
    }
    if (det.hardRule) {
      assert.ok(
        Array.isArray(row.suppressWith) && row.suppressWith.length > 0,
        `${det.id} suppress`,
      );
      for (const entry of row.suppressWith) {
        assert.notStrictEqual(entry.method, 'allow', `${det.id} allow`);
        if (
          entry.method === 'suppress' &&
          entry.args[2] &&
          typeof entry.args[2].untilTs === 'number'
        ) {
          assert.ok(entry.args[2].untilTs <= anomaly.ts + DAY, `${det.id} untilTs`);
        }
      }
    }
  }
});
