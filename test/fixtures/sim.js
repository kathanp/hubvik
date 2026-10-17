'use strict';

const { mulberry32, range } = require('./prng');
const { T0, H, DAY } = require('./clock');
const { PROFILES } = require('./profiles');

/**
 * @param {{ hosts: string[], hostPick?: string }} spec
 * @param {number} n
 * @returns {string}
 */
function pickHost(spec, n) {
  if (spec.hostPick === 'tenth') return n % 10 === 0 ? spec.hosts[1] : spec.hosts[0];
  if (spec.hostPick === 'mod') return spec.hosts[n % spec.hosts.length];
  return spec.hosts[0];
}

/**
 * T0 connection summaries for one benign device class.
 * @param {{ profile: string, days: number, seed?: number, startTs?: number, rich?: boolean }} opts
 * @returns {object[]}
 */
function simulate(opts) {
  const spec = PROFILES[opts.profile];
  if (!spec) throw new Error(`unknown profile ${opts.profile}`);
  if (!Number.isInteger(opts.days) || opts.days < 1)
    throw new Error('days must be a positive integer');
  const rng = mulberry32(opts.seed ?? 1);
  const origin = opts.startTs ?? T0;
  const minuteLimit = (spec.minutes ?? 60) * 60_000;
  /** @type {{ device: string, dst: string, bytes: number, ts: number }[]} */
  const events = [];
  let n = 0;
  for (let day = 0; day < opts.days; day++) {
    for (const hour of spec.hours) {
      for (let ms = 0; ms < minuteLimit; ms += spec.everyMs) {
        const jitter = spec.jitter ?? 0;
        const scale = 1 + range(rng, -jitter, jitter);
        events.push({
          device: spec.device,
          dst: pickHost(spec, n),
          bytes: Math.max(1, Math.round(spec.bytes * scale)),
          ts: origin + day * DAY + hour * H + ms,
        });
        n += 1;
      }
    }
  }
  if (!opts.rich) return events;
  return enrich(spec, events, origin, opts.days);
}

/**
 * Same schedule as the summaries, expressed as flow, DNS, TLS, link, and app events.
 * Summaries are omitted so window bytes are not counted twice.
 * @param {{ device: string, hosts: string[], bytes: number, hours: number[] }} spec
 * @param {{ device: string, dst: string, bytes: number, ts: number }[]} summaries
 * @param {number} origin
 * @param {number} days
 */
function enrich(spec, summaries, origin, days) {
  /** @type {object[]} */
  const events = [];
  const mac = 'aa:bb:cc:dd:ee:01';
  const resolver = '192.0.2.1';
  let lease = '192.0.2.10';
  for (let day = 0; day < days; day++) {
    const dayStart = origin + day * DAY + spec.hours[0] * H;
    if (day === 2) lease = '192.0.2.11';
    events.push({
      type: 'dhcp',
      device: spec.device,
      ts: dayStart,
      mac,
      msg: 'ack',
      serverIp: resolver,
      requestedIp: lease,
    });
    events.push({
      type: 'arp',
      device: spec.device,
      ts: dayStart + 1,
      ip: lease,
      mac,
      op: 'reply',
    });
    events.push(ntp(spec.device, dayStart + 2_000, '1.1.1.1', lease));
    events.push(ntp(spec.device, dayStart + 3_000, '9.9.9.9', lease));
  }
  const firmwareAt = origin + DAY + 12 * H;
  events.push({
    type: 'flow',
    device: spec.device,
    ts: firmwareAt,
    srcIp: '192.0.2.10',
    srcPort: 41000,
    dstIp: '1.2.3.50',
    dstPort: 443,
    proto: 'tcp',
    direction: 'in',
    bytesOut: 2000,
    bytesIn: 30_000_000,
    pktsOut: 4,
    pktsIn: 20000,
    durationMs: 4000,
    tcpOutcome: 'established',
    dstName: 'update.vendor.com',
  });
  for (const summary of summaries) {
    const host = summary.dst;
    const flip = Math.floor(summary.ts / 60_000) % 2 === 0;
    const dstIp = flip ? '1.2.3.10' : '1.2.3.11';
    const upload = Math.max(1, Math.round(summary.bytes * 0.02));
    const download = Math.max(1, summary.bytes - upload);
    const dayIndex = Math.floor((summary.ts - origin) / DAY);
    const srcIp = dayIndex >= 2 ? '192.0.2.11' : '192.0.2.10';
    events.push({
      type: 'dns',
      device: spec.device,
      ts: summary.ts,
      qname: host,
      qtype: 'A',
      rcode: 'NOERROR',
      resolver,
      answers: [{ type: 'A', value: dstIp, ttl: 300 }],
    });
    events.push({
      type: 'flow',
      device: spec.device,
      ts: summary.ts,
      srcIp,
      srcPort: 40000,
      dstIp,
      dstPort: host.startsWith('mqtt.') ? 8883 : 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: upload,
      bytesIn: download,
      pktsOut: 2,
      pktsIn: 2,
      durationMs: 40,
      tcpOutcome: 'established',
      dstName: host,
    });
    events.push({
      type: 'tls',
      device: spec.device,
      ts: summary.ts,
      dstIp,
      dstPort: host.startsWith('mqtt.') ? 8883 : 443,
      sni: host,
      ja4: 't13d1516h2_8daaf6152771_vendor',
      version: 'TLSv1.3',
      cert: { issuer: 'Vendor CA', selfSigned: false, notAfter: origin + 400 * DAY },
    });
    if (spec.device === 'thermostat-1') {
      events.push({
        type: 'app',
        device: spec.device,
        ts: summary.ts,
        proto: 'mqtt',
        role: 'client',
        peerIp: dstIp,
        op: 'PUBLISH',
        target: 'home/status',
        result: 'ok',
      });
    }
    if (spec.device === 'hvac-1') {
      events.push({
        type: 'app',
        device: spec.device,
        ts: summary.ts,
        proto: 'bacnet',
        role: 'server',
        peerIp: '10.0.0.2',
        op: 'ReadProperty',
        target: 'setpoint',
        value: 21,
        result: 'ok',
      });
      events.push({
        type: 'app',
        device: spec.device,
        ts: summary.ts,
        proto: 'bacnet',
        role: 'server',
        peerIp: '10.0.0.2',
        op: 'WriteProperty',
        target: 'setpoint',
        value: 21,
        result: 'ok',
      });
    }
  }
  events.sort((a, b) => a.ts - b.ts);
  return events;
}

/**
 * @param {string} device
 * @param {number} ts
 * @param {string} dstIp
 * @param {string} srcIp
 */
function ntp(device, ts, dstIp, srcIp) {
  return {
    type: 'flow',
    device,
    ts,
    srcIp,
    srcPort: 40001,
    dstIp,
    dstPort: 123,
    proto: 'udp',
    direction: 'out',
    bytesOut: 48,
    bytesIn: 48,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 20,
    dstName: dstIp === '1.1.1.1' ? 'time.cloudflare.com' : 'dns.quad9.net',
  };
}

module.exports = { simulate };
