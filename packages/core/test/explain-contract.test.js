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
};

/**
 * @param {string} id
 */
const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

function optionsFor(id) {
  /** @type {any} */
  const options = { tiers: TIERS, learnMs: 0 };
  if (id === 'alert-storm') options.detectors = { 'alert-storm': { maxPerMinute: 1 } };
  if (id === 'new-device' || id === 'spam-relay') options.learnMs = 1000;
  if (id === 'clock-jump') options.learnMs = 86400000;
  if (id === 'horizontal-scan' || id === 'dns-tunnel') options.learnMs = 86400000;
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
