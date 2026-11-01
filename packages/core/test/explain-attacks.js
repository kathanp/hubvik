'use strict';

const DAY = 86_400_000;
const HOUR = 3600e3;

/**
 * Engine options the crafted feed needs before the first event.
 * @param {string} id
 * @returns {Record<string, unknown>}
 */
function optionsForAttack(id) {
  if (id === 'browser-mimic') return { browserJa4: ['t13dbrowser_ja4'] };
  if (id === 'zone-violation' || id === 'ntp-rogue') {
    return {
      gatewayIp: '10.0.0.1',
      zones: [
        { id: 'iot', cidr: '10.1.0.0/16' },
        { id: 'lan', cidr: '10.2.0.0/16' },
      ],
    };
  }
  if (id === 'new-asn' || id === 'new-country') {
    return { lookup: () => ({ asn: 'AS9', country: 'ZZ' }) };
  }
  if (id === 'answer-drift') {
    return {
      learnMs: DAY,
      lookup: (ip) => ({ asn: ip === '1.1.1.1' ? 'AS1' : 'AS2', country: 'US' }),
    };
  }
  if (
    id === 'cert-change' ||
    id === 'went-silent' ||
    id === 'slow-exfil' ||
    id === 'peer-divergence' ||
    id === 'identity-change' ||
    id === 'ot-value-out-of-range' ||
    id === 'ot-write-new' ||
    id === 'ot-recon' ||
    id === 'ot-spoof' ||
    id === 'upload-ratio-shift'
  ) {
    return { learnMs: id === 'went-silent' ? 7 * DAY : id === 'slow-exfil' ? 10 * HOUR : DAY };
  }
  return {};
}

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

/**
 * @param {any} engine
 * @param {string} qname
 * @param {number} ts
 * @param {any[]} [answers]
 * @param {string} [rcode]
 */
function dns(engine, qname, ts, answers, rcode) {
  engine.feed({
    type: 'dns',
    device: 'd',
    ts,
    qname,
    qtype: 'A',
    rcode: rcode || 'NOERROR',
    resolver: '10.0.0.1',
    answers,
  });
}

/** @type {Record<string, (engine: any) => void>} */
const ATTACKS = {
  'ad-fraud'(engine) {
    engine.loadIndicators([
      { value: 'doubleclick.net', type: 'ad', source: 'lab' },
      { value: 'ads.example', type: 'ad', source: 'lab' },
    ]);
    for (let i = 0; i < 5; i++) dns(engine, `${i}.doubleclick.net`, 1000 + i);
  },
  'answer-drift'(engine) {
    dns(engine, 'video.vendor.com', 1000, [{ type: 'A', value: '1.1.1.1', ttl: 300 }]);
    engine.lock('d');
    dns(engine, 'video.vendor.com', 200_000, [{ type: 'A', value: '8.8.8.8', ttl: 300 }]);
  },
  'bogon-destination'(engine) {
    engine.feed(flow({ dstIp: '10.1.2.3' }));
  },
  'browser-mimic'(engine) {
    engine.setDeviceClass('d', 'camera');
    engine.feed(tls({ ja4: 't13dbrowser_ja4' }));
  },
  'brute-force-in'(engine) {
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
  },
  'cert-change'(engine) {
    engine.feed(tls({ ts: 1000 }));
    engine.lock('d');
    engine.feed(tls({ ts: 2100, cert: { issuer: 'Evil CA' } }));
  },
  'cleartext-regression'(engine) {
    engine.feed(tls({ ts: 1000 }));
    engine.feed({
      type: 'http',
      device: 'd',
      ts: 2400,
      dstIp: '1.2.3.4',
      dstPort: 80,
      method: 'GET',
      host: 'video.vendor.com',
    });
  },
  'connection-churn'(engine) {
    for (let i = 0; i < 51; i++) engine.feed(flow({ ts: 1000 + i, dstIp: `1.2.8.${i % 20}` }));
    engine.flush(60_000);
  },
  'credential-stuffing-out'(engine) {
    for (let i = 0; i < 15; i++) {
      engine.feed(flow({ ts: 230_000, dstName: `login${i}.example`, dstIp: '1.2.3.40' }));
    }
  },
  dga(engine) {
    for (let i = 0; i < 5; i++) dns(engine, `qxvzkplmnbw${i}.example`, 2000);
  },
  'dhcp-starvation'(engine) {
    for (let i = 0; i < 21; i++) {
      engine.feed({
        type: 'dhcp',
        device: 'd',
        ts: 1500,
        mac: `02:00:00:00:00:${i.toString(16).padStart(2, '0')}`,
        msg: 'discover',
      });
    }
  },
  'direct-ip'(engine) {
    engine.feed(flow({ ts: 3000, dstIp: '8.8.8.8' }));
  },
  'dns-rebinding'(engine) {
    dns(engine, 'camera.example', 1000, [{ type: 'A', value: '10.0.0.9', ttl: 30 }]);
  },
  'failed-connection-ratio'(engine) {
    for (let i = 0; i < 20; i++) {
      engine.feed(flow({ ts: 1000 + i, tcpOutcome: 'rejected', dstIp: `1.2.9.${i}` }));
    }
    engine.flush(60_000);
  },
  'fan-out'(engine) {
    for (let i = 0; i < 12; i++)
      engine.feed({ device: 'd', dst: `scan-${i}.example`, bytes: 60, ts: i });
  },
  'fast-flux'(engine) {
    const answers = [];
    for (let i = 1; i <= 8; i++) answers.push({ type: 'A', value: `203.0.113.${i}`, ttl: 5 });
    dns(engine, 'flux.example', 210_000, answers);
  },
  'fleet-wave'(engine) {
    for (let i = 0; i < 3; i++) {
      engine.feed({ device: `cam-${i}`, dst: 'wave.example', bytes: 10, ts: 1000 + i });
    }
  },
  'gratuitous-arp-flood'(engine) {
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
  },
  'icmp-tunnel'(engine) {
    engine.feed(flow({ ts: 2300, proto: 'icmp', bytesOut: 1000, pktsOut: 1, icmpType: 8 }));
  },
  'identity-change'(engine) {
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 1000,
      mac: 'aa',
      msg: 'request',
      fingerprint: 'one',
    });
    engine.lock('d');
    engine.feed({
      type: 'dhcp',
      device: 'd',
      ts: 2000,
      mac: 'aa',
      msg: 'request',
      fingerprint: 'two',
    });
  },
  'ipv6-tunnel'(engine) {
    engine.feed(flow({ ts: 2400, proto: 41 }));
  },
  'lan-lateral'(engine) {
    engine.feed(flow({ ts: 1000, direction: 'lan', dstIp: '10.0.0.20', srcIp: '10.0.0.8' }));
  },
  'lan-sweep'(engine) {
    for (let i = 1; i <= 21; i++) {
      engine.feed(
        flow({
          ts: 1200,
          proto: 'icmp',
          dstIp: `10.0.0.${i}`,
          direction: 'lan',
          srcIp: '10.0.0.8',
        }),
      );
    }
  },
  'lan-via-proxy'(engine) {
    engine.feed(flow({ ts: 2000, durationMs: 120_000, dstIp: '9.9.9.9' }));
    for (let i = 0; i < 8; i++)
      engine.feed(flow({ ts: 2500 + i, durationMs: 100, dstIp: `9.9.8.${i}` }));
    engine.feed(
      flow({ ts: 4000, direction: 'in', bytesIn: 500, srcIp: '203.0.113.9', dstIp: '10.0.0.8' }),
    );
    engine.feed(flow({ ts: 4500, direction: 'lan', dstIp: '10.0.0.20', srcIp: '10.0.0.8' }));
  },
  'long-connection'(engine) {
    engine.feed(flow({ ts: 1000, durationMs: 700_000, dstIp: '198.51.100.21' }));
  },
  'mqtt-new-broker'(engine) {
    engine.feed(flow({ ts: 1000, dstPort: 1883, dstIp: '198.51.100.40' }));
  },
  'mqtt-publish-rate'(engine) {
    for (let i = 0; i < 31; i++)
      engine.feed(app('cam', 8000, '10.0.0.3', 'mqtt', 'PUBLISH', 'home/status'));
  },
  'mqtt-topic-new'(engine) {
    engine.feed(app('cam', 1200, '10.0.0.3', 'mqtt', 'PUBLISH', 'home/status'));
    engine.lock('cam');
    engine.feed(app('cam', 7100, '10.0.0.3', 'mqtt', 'PUBLISH', 'cmd/reboot'));
  },
  'mqtt-wildcard-subscribe'(engine) {
    engine.feed(app('cam', 7000, '10.0.0.3', 'mqtt', 'SUBSCRIBE', '#'));
  },
  'new-asn'(engine) {
    engine.feed(flow({ ts: 1000, dstIp: '8.8.8.8' }));
  },
  'new-client-fingerprint'(engine) {
    engine.feed(tls({ ts: 1000 }));
  },
  'new-country'(engine) {
    engine.feed(flow({ ts: 1000, dstIp: '8.8.8.8' }));
  },
  'new-destination'(engine) {
    engine.feed({ device: 'd', dst: 'new.example', bytes: 10, ts: 1000 });
  },
  'new-domain-family'(engine) {
    engine.feed({ device: 'd', dst: 'new.example', bytes: 10, ts: 1000 });
  },
  'new-port'(engine) {
    engine.feed(flow({ ts: 1000, dstPort: 7547 }));
  },
  'ntp-rogue'(engine) {
    engine.feed(flow({ ts: 2500, proto: 'udp', dstPort: 123, dstIp: '9.9.9.9' }));
  },
  'nxdomain-burst'(engine) {
    for (let i = 0; i < 11; i++) dns(engine, `missing${i}.example`, 1000, undefined, 'NXDOMAIN');
    engine.flush(60_000);
  },
  'ot-error-burst'(engine) {
    for (let i = 0; i < 11; i++) {
      engine.feed(app('ahu', 4000, '10.0.0.2', 'bacnet', 'ReadProperty', 'x', undefined, 'error'));
    }
  },
  'ot-new-master'(engine) {
    engine.feed(app('ahu', 1000, '10.0.0.9', 'bacnet', 'I-Am', 'device-7'));
  },
  'ot-recon'(engine) {
    engine.feed(app('ahu', 1000, '10.0.0.2', 'bacnet', 'I-Am', 'device-7'));
    engine.lock('ahu');
    for (let i = 0; i < 11; i++) {
      engine.feed(app('ahu', 3000 + i, `10.1.0.${i}`, 'bacnet', 'Who-Is', `n${i}`));
    }
  },
  'ot-spoof'(engine) {
    engine.feed(app('ahu', 1000, '10.0.0.2', 'bacnet', 'I-Am', 'device-7'));
    engine.lock('ahu');
    engine.feed(app('ahu', 5000, '10.0.0.9', 'bacnet', 'I-Am', 'device-7'));
  },
  'ot-value-out-of-range'(engine) {
    for (let i = 0; i < 3; i++)
      engine.feed(app('ahu', 1000 + i, '10.0.0.2', 'bacnet', 'WriteProperty', 'setpoint', 20));
    engine.lock('ahu');
    engine.feed(app('ahu', 5000, '10.0.0.2', 'bacnet', 'WriteProperty', 'setpoint', 40));
  },
  'ot-write-new'(engine) {
    engine.feed(app('ahu', 1000, '10.0.0.2', 'bacnet', 'WriteProperty', 'fan', 1));
    engine.lock('ahu');
    engine.feed(app('ahu', 2000, '10.0.0.2', 'bacnet', 'WriteProperty', 'damper', 1));
  },
  'ot-write-rate'(engine) {
    for (let i = 0; i < 12; i++) {
      engine.feed(app('ahu', 6000 + i, '10.0.0.2', 'bacnet', 'WriteProperty', 'fan', 1));
    }
    engine.flush(120_000);
  },
  'p2p-pattern'(engine) {
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
  },
  'peer-divergence'(engine) {
    for (let i = 0; i < 5; i++) {
      engine.setPeerGroup(`p${i}`, 'cams');
      engine.feed({ device: `p${i}`, dst: 'video.vendor.com', bytes: 10, ts: 1000 });
    }
    engine.setPeerGroup('odd', 'cams');
    engine.feed({ device: 'odd', dst: 'video.vendor.com', bytes: 10, ts: 1000 });
    engine.lock('odd');
    engine.feed({ device: 'odd', dst: 'evil.example', bytes: 10, ts: 2000 });
  },
  'posture-cleartext-auth'(engine) {
    engine.feed(flow({ ts: 1400, dstPort: 23, proto: 'tcp' }));
  },
  'posture-listening-risky'(engine) {
    engine.feed(
      flow({ ts: 1000, direction: 'in', dstPort: 23, dstIp: '10.0.0.8', srcIp: '198.51.100.9' }),
    );
  },
  'posture-wan-exposed'(engine) {
    engine.feed(
      flow({ ts: 1000, direction: 'in', srcIp: '8.8.8.8', dstIp: '10.0.0.8', dstPort: 80 }),
    );
  },
  'posture-weak-tls'(engine) {
    engine.feed(tls({ ts: 1100, version: 'TLSv1.0', ja4: 'other', dstIp: '1.2.3.5' }));
  },
  'private-answer-for-public-name'(engine) {
    dns(engine, 'camera.example', 1000, [{ type: 'A', value: '10.1.2.3', ttl: 30 }]);
  },
  'proxy-backconnect'(engine) {
    engine.feed(flow({ ts: 2000, durationMs: 120_000, dstIp: '9.9.9.9' }));
    for (let i = 0; i < 8; i++)
      engine.feed(flow({ ts: 2500 + i, durationMs: 100, dstIp: `9.9.8.${i}` }));
  },
  'quic-new'(engine) {
    engine.feed(flow({ ts: 240_000, proto: 'udp', dstPort: 443, dstIp: '9.9.9.1' }));
  },
  'resolver-bypass'(engine) {
    dns(engine, 'video.vendor.com', 1000, undefined, 'NOERROR');
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 1100,
      qname: 'a.example',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '8.8.8.8',
    });
  },
  'slow-exfil'(engine) {
    for (let hour = 0; hour <= 6; hour++) {
      engine.feed(flow({ ts: hour * HOUR, bytesOut: 1000, pktsOut: 10 }));
    }
    engine.lock('d');
    engine.feed(flow({ ts: 7 * HOUR, bytesOut: 5_000_000, pktsOut: 10 }));
  },
  'sni-missing'(engine) {
    engine.feed(
      tls({ ts: 2200, sni: undefined, dstIp: '198.51.100.8', ja4: undefined, cert: undefined }),
    );
  },
  'stream-to-new-destination'(engine) {
    engine.feed(flow({ ts: 1000, dstPort: 554, dstIp: '198.51.100.40' }));
  },
  'tls-on-odd-port'(engine) {
    engine.feed(tls({ ts: 2300, dstPort: 8443 }));
  },
  'tunnel-service'(engine) {
    dns(engine, 'host.ngrok.io', 2100);
  },
  'update-from-new-source'(engine) {
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
  },
  'update-over-cleartext'(engine) {
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
  },
  'upload-ratio-shift'(engine) {
    for (let i = 0; i < 6; i++) {
      engine.feed(flow({ ts: i * 60_000, bytesOut: 1000, bytesIn: 20_000 }));
      engine.flush((i + 1) * 60_000);
    }
    engine.lock('d');
    engine.feed(flow({ ts: 7 * 60_000, bytesOut: 20_000, bytesIn: 100 }));
    engine.flush(8 * 60_000);
  },
  'upnp-port-open'(engine) {
    engine.feed({
      type: 'mapping',
      device: 'd',
      ts: 1000,
      proto: 'upnp',
      port: 5555,
      externalPort: 5555,
    });
  },
  'vertical-scan'(engine) {
    for (let port = 1; port <= 16; port++)
      engine.feed(flow({ ts: 1000, dstPort: port, dstIp: '198.51.100.9' }));
  },
  'volume-spike'(engine) {
    engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 2_000_000, ts: 1000 });
    engine.flush(60_000);
  },
  'volume-spike-hourly'(engine) {
    engine.feed({ device: 'd', dst: 'video.vendor.com', bytes: 2_000_000, ts: 1000 });
    engine.flush(60_000);
  },
  'vpn-protocol'(engine) {
    engine.feed(flow({ ts: 2200, proto: 'udp', dstPort: 51820, bytesOut: 148 }));
  },
  'went-silent'(engine) {
    const start = Date.UTC(2026, 0, 5, 13, 0, 0);
    for (let i = 0; i < 9; i++) {
      engine.feed({
        device: 'cam',
        dst: 'video.vendor.com',
        bytes: 100,
        ts: start + i * 5 * 60_000,
      });
    }
    engine.lock('cam');
    engine.tick(start + 8 * 5 * 60_000 + 16 * 60_000);
  },
  'wrong-time'(engine) {
    engine.feed({
      device: 'd',
      dst: 'video.vendor.com',
      bytes: 10,
      ts: Date.UTC(2026, 0, 5, 3, 0, 0),
    });
  },
  'zone-violation'(engine) {
    engine.feed(flow({ ts: 2000, direction: 'lan', srcIp: '10.1.0.8', dstIp: '10.2.0.9' }));
  },
};

module.exports = { ATTACKS, optionsForAttack };
