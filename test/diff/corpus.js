'use strict';

const { simulate } = require('../fixtures/sim');
const { CLASS_NAMES } = require('../fixtures/profiles');
const { T0, DAY } = require('../fixtures/clock');
const { fanout, volumeBurst } = require('../fixtures/attacks');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {import('../../packages/core/src/index.js').Engine} engine
 * @returns {{ detector: string, device: string, ts: number, severity: string, data: unknown }[]}
 */
function listen(engine) {
  /** @type {{ detector: string, device: string, ts: number, severity: string, data: unknown }[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => {
    anomalies.push({
      detector: item.detector,
      device: item.device,
      ts: item.ts,
      severity: item.severity,
      data: item.data,
    });
  });
  return anomalies;
}

/**
 * @param {import('../../packages/core/src/index.js').Engine} engine
 * @param {{ detector: string, device: string, ts: number, severity: string, data: unknown }[]} anomalies
 */
function finish(engine, anomalies) {
  return {
    anomalies,
    baseline: engine.exportBaseline({ createdAt: 1 }),
  };
}

/**
 * @param {number} ts
 * @param {string} peer
 * @param {string} op
 * @param {string} target
 * @param {number | string} [value]
 */
function app(ts, peer, op, target, value) {
  return {
    type: 'app',
    device: 'ahu-1',
    ts,
    proto: 'bacnet',
    role: 'server',
    peerIp: peer,
    op,
    target,
    value,
    result: 'ok',
  };
}

/**
 * The replay tests, both attack generators, and the all-tier benign matrix.
 * @param {typeof import('../../packages/core/src/index.js').createEngine} createEngine
 */
function capture(createEngine) {
  /** @type {Record<string, { anomalies: unknown[], baseline: unknown }>} */
  const out = Object.create(null);

  {
    const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T0', 'T1'] });
    const anomalies = listen(engine);
    for (let i = 1; i <= 12; i++) {
      engine.feed({
        type: 'flow',
        device: 'cam',
        ts: 5000,
        srcIp: '10.0.0.8',
        srcPort: 50000 + i,
        dstIp: `1.2.3.${i}`,
        dstPort: 23,
        proto: 'tcp',
        direction: 'out',
        bytesOut: 40,
        bytesIn: 0,
        pktsOut: 1,
        pktsIn: 0,
        durationMs: 15,
      });
    }
    engine.feed({
      type: 'flow',
      device: 'cam',
      ts: 6000,
      srcIp: '10.0.0.8',
      srcPort: 0,
      dstIp: '198.51.100.10',
      dstPort: 0,
      proto: 'gre',
      direction: 'out',
      bytesOut: 8000,
      bytesIn: 0,
      pktsOut: 800,
      pktsIn: 0,
      durationMs: 1000,
    });
    out['replay:mirai-like'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T0', 'T1', 'T2'] });
    const anomalies = listen(engine);
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
    for (let i = 1; i <= 12; i++) {
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
    out['replay:kimwolf-like'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({
      shadow: true,
      learnMs: 7 * 24 * 3600e3,
      tiers: ['T0', 'T1', 'T2'],
    });
    engine.setDeviceClass('box', 'tv-box');
    const anomalies = listen(engine);
    const names = [
      'www.amazon.com',
      'www.ebay.com',
      'www.facebook.com',
      'www.tiktok.com',
      'www.ticketmaster.com',
      'www.eventbrite.com',
    ];
    names.forEach((dstName, index) => {
      engine.feed({
        type: 'flow',
        device: 'box',
        ts: 60_000 + index,
        srcIp: '10.0.0.20',
        srcPort: 41000,
        dstIp: `1.1.1.${index + 1}`,
        dstPort: 443,
        proto: 'tcp',
        direction: 'out',
        bytesOut: 800,
        bytesIn: 4000,
        pktsOut: 6,
        pktsIn: 8,
        durationMs: 200,
        dstName,
      });
    });
    out['replay:badbox-like'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T0', 'T3'] });
    const anomalies = listen(engine);
    engine.feed({
      type: 'tls',
      device: 'cam',
      ts: 1000,
      dstIp: '1.2.3.4',
      dstPort: 443,
      sni: 'video.vendor.com',
      cert: { issuer: 'Vendor CA' },
    });
    engine.lock('cam');
    engine.feed({
      type: 'tls',
      device: 'cam',
      ts: 5000,
      dstIp: '1.2.3.4',
      dstPort: 443,
      sni: 'video.vendor.com',
      cert: { issuer: 'Unexpected CA' },
    });
    out['replay:mitm'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T0', 'T5'] });
    const anomalies = listen(engine);
    for (const value of [20, 21, 22]) {
      engine.feed(app(1000 + value, '10.0.0.2', 'WriteProperty', 'setpoint', value));
    }
    engine.lock('ahu-1');
    engine.feed(app(5000, '10.0.0.9', 'WriteProperty', 'setpoint', 21));
    engine.feed(app(6000, '10.0.0.2', 'WriteProperty', 'setpoint', 40));
    engine.feed(app(7000, '10.0.0.9', 'DeviceCommunicationControl', 'device'));
    out['replay:bms-hijack'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 86_400_000, tiers: ['T1'] });
    const anomalies = listen(engine);
    engine.feed({
      type: 'flow',
      device: 'cam',
      ts: 1_000,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: '1.2.3.4',
      dstPort: 443,
      proto: 'udp',
      direction: 'out',
      bytesOut: 60_000 * 1_400,
      bytesIn: 0,
      pktsOut: 60_000,
      pktsIn: 0,
      durationMs: 1_000,
    });
    out['replay:large-udp-flood'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 0, tiers: ['T1', 'T2'] });
    engine.setDeviceClass('tv', 'smart-tv');
    engine.loadIndicators([
      { value: 'sdk.proxy.example', type: 'proxy-sdk', source: 'lab', confidence: 0.9 },
    ]);
    const anomalies = listen(engine);
    engine.feed({
      type: 'dns',
      device: 'tv',
      ts: 1_000,
      qname: 'sdk.proxy.example',
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
      answers: [{ type: 'A', value: '1.2.3.9', ttl: 30 }],
    });
    engine.feed({
      type: 'flow',
      device: 'tv',
      ts: 2_000,
      srcIp: '1.2.3.9',
      srcPort: 443,
      dstIp: '10.0.0.20',
      dstPort: 50000,
      proto: 'tcp',
      direction: 'in',
      bytesOut: 0,
      bytesIn: 200,
      pktsOut: 0,
      pktsIn: 2,
      durationMs: 40,
    });
    engine.feed({
      type: 'flow',
      device: 'tv',
      ts: 2_400,
      srcIp: '10.0.0.20',
      srcPort: 50000,
      dstIp: '10.0.0.50',
      dstPort: 80,
      proto: 'tcp',
      direction: 'lan',
      bytesOut: 100,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 40,
    });
    out['replay:smart-tv-proxy-sdk'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: TIERS });
    const anomalies = listen(engine);
    engine.feed(volumeBurst('cam', 0, 1_000_000));
    engine.flush(60_000);
    out['attacks:volume-burst'] = finish(engine, anomalies);
  }

  {
    const engine = createEngine({ shadow: true, learnMs: 60_000, tiers: TIERS });
    const anomalies = listen(engine);
    for (const event of fanout('cam', 0, 25)) engine.feed(event);
    engine.flush(60_000);
    out['attacks:fan-out'] = finish(engine, anomalies);
  }

  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      const events = simulate({ profile, days: 14, seed, startTs: T0, rich: true });
      const engine = createEngine({ shadow: true, learnMs: 7 * DAY, tiers: TIERS });
      engine.setDeviceClass(events[0].device, profile);
      const anomalies = listen(engine);
      for (const event of events) engine.feed(event);
      engine.flush(T0 + 14 * DAY);
      out[`benign:${profile}:seed${seed}`] = finish(engine, anomalies);
    }
  }

  return out;
}

module.exports = { capture };
