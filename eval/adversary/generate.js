'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createEngine, detectors, SEVERITY } = require('hubvik');
const { mulberry32 } = require('../../test/fixtures/prng.js');
const published = require('./params.js');

const HOUR = 60 * 60 * 1000;
const CDN = new Set([
  'cloudfront.net',
  'akamai.net',
  'akamaized.net',
  'fastly.net',
  'cloudflare.net',
  'edgekey.net',
]);

/**
 * Engine options shared by the learning run and each attack run.
 * @returns {object}
 */
function engineOptions() {
  return {
    learnMs: 1e14,
    tiers: ['T0', 'T1', 'T2', 'T3', 'T5'],
    evidence: false,
  };
}

/**
 * @param {number} ts
 * @returns {number}
 */
function hourOf(ts) {
  return Math.floor(ts / HOUR) % 24;
}

/**
 * @param {object} params
 * @param {number} day
 * @param {number} hour
 * @param {number} offsetMs
 * @returns {number}
 */
function at(params, day, hour, offsetMs) {
  return day * params.DAY + hour * HOUR + offsetMs;
}

/**
 * @param {object} params
 * @param {number} ts
 * @param {string} dst
 * @param {number} bytes
 * @returns {object}
 */
function summary(params, ts, dst, bytes) {
  return { type: 'summary', device: params.DEVICE, ts, dst, bytes };
}

/**
 * @param {object} params
 * @param {number} ts
 * @param {string} qname
 * @returns {object}
 */
function dns(params, ts, qname) {
  return {
    type: 'dns',
    device: params.DEVICE,
    ts,
    qname,
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.53',
    answers: [{ type: 'A', value: params.BEACON_IP, ttl: 300 }],
  };
}

/**
 * @param {object} params
 * @param {number} ts
 * @param {string} sni
 * @param {string | null} ja4
 * @returns {object}
 */
function tls(params, ts, sni, ja4) {
  /** @type {Record<string, unknown>} */
  const event = {
    type: 'tls',
    device: params.DEVICE,
    ts,
    dstIp: params.BEACON_IP,
    dstPort: 443,
    sni,
    version: 'TLS1.3',
  };
  if (ja4) event.ja4 = ja4;
  return event;
}

/**
 * @param {object} params
 * @param {number} ts
 * @param {string} dstIp
 * @param {number} dstPort
 * @param {number} bytesOut
 * @param {string | null} dstName
 * @returns {object}
 */
function flow(params, ts, dstIp, dstPort, bytesOut, dstName) {
  /** @type {Record<string, unknown>} */
  const event = {
    type: 'flow',
    device: params.DEVICE,
    ts,
    srcIp: params.SRC_IP,
    srcPort: 40000,
    dstIp,
    dstPort,
    proto: 'tcp',
    direction: 'out',
    bytesOut,
    bytesIn: bytesOut,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
  };
  if (dstName) event.dstName = dstName;
  return event;
}

/**
 * @param {object} params
 * @param {number} ts
 * @param {number} value
 * @returns {object}
 */
function writeSetpoint(params, ts, value) {
  return {
    type: 'app',
    device: params.DEVICE,
    ts,
    proto: 'modbus',
    role: 'client',
    peerIp: params.OT_PEER,
    op: 'write',
    target: params.OT_TARGET,
    value,
    result: 'ok',
  };
}

/**
 * Benign profile: active hours, a CDN family, a vendor family, a JA4, a beacon, and an OT range.
 * @param {object} params
 * @returns {object[]}
 */
function learningEvents(params) {
  /** @type {object[]} */
  const events = [];
  for (let day = 0; day < params.LEARN_DAYS; day += 1) {
    for (let index = 0; index < params.ACTIVE_HOURS.length; index += 1) {
      const hour = params.ACTIVE_HOURS[index];
      const ts = at(params, day, hour, 0);
      const cdn = params.CDN_HOSTS[index % params.CDN_HOSTS.length];
      events.push(summary(params, ts, cdn, 1000));
      events.push(summary(params, ts + 1, params.VENDOR_HOST, 1000));
      events.push(dns(params, ts + 2, cdn));
      events.push(dns(params, ts + 3, params.VENDOR_HOST));
      events.push(tls(params, ts + 4, cdn, params.JA4));
      events.push(
        flow(params, ts + 5, params.BEACON_IP, 443, params.LEARN_BYTES, params.VENDOR_HOST),
      );
      if (index < params.OT_VALUES.length) {
        events.push(writeSetpoint(params, ts + 6, params.OT_VALUES[index]));
      }
    }
  }
  return events;
}

/**
 * @param {object} baseline
 * @param {object} params
 * @returns {object}
 */
function readEnvelope(baseline, params) {
  const device = baseline.devices && baseline.devices[params.DEVICE];
  if (!device || !device.detectors) throw new Error('baseline has no target device');
  /**
   * @param {string} id
   * @returns {any}
   */
  const state = (id) => {
    const row = device.detectors[id];
    return row && row.state ? row.state : null;
  };
  const wrong = state('wrong-time');
  const families = (state('new-domain-family') && state('new-domain-family').families) || [];
  const seen = (state('new-client-fingerprint') && state('new-client-fingerprint').seen) || [];
  const ranges = (state('ot-value-out-of-range') && state('ot-value-out-of-range').ranges) || [];
  const slow = state('slow-exfil');
  let mean = 0;
  let bytesPerHour = null;
  if (slow && Array.isArray(slow.samples) && slow.samples.length > 0) {
    let sum = 0;
    for (const sample of slow.samples) sum += Number(sample);
    mean = sum / slow.samples.length;
    bytesPerHour = Math.max(5 * mean, 1e6);
  }
  const scan = state('horizontal-scan');
  let learnedHosts = 0;
  if (scan && Array.isArray(scan.max)) {
    for (const pair of scan.max) {
      if (Array.isArray(pair) && typeof pair[1] === 'number') {
        learnedHosts = Math.max(learnedHosts, pair[1]);
      }
    }
  }
  const hs = detectors['horizontal-scan'].defaults;
  const churn = state('connection-churn');
  const ch = detectors['connection-churn'].defaults;
  const fan = state('fan-out');
  const fo = detectors['fan-out'].defaults;
  const vol = detectors['volume-spike'].defaults;
  const hostsPerWindow = Math.max(hs.minHosts, hs.factor * learnedHosts);
  const flowsPerWindow = Math.max(ch.minCount, ch.factor * ((churn && churn.max) || 0));
  const fanout = Math.max(fo.minFanout, ((fan && fan.max) || 0) * fo.fanoutFactor);
  const bytesPerWindow = windowByteLimit(state('volume-spike'), vol);
  /** @type {(number | null)[]} */
  const hourWindowBytes = [];
  const hourly = state('volume-spike-hourly');
  for (let hour = 0; hour < 24; hour += 1) {
    const row = hourly && Array.isArray(hourly.hours) ? hourly.hours[hour] : null;
    hourWindowBytes.push(windowByteLimit(row, vol));
  }
  return {
    hours: wrong && Array.isArray(wrong.hours) ? wrong.hours.slice() : [],
    families: families.slice(),
    cdn: families.filter((family) => CDN.has(family)),
    ja4: seen.length > 0 ? String(seen[0]) : null,
    ranges,
    mean,
    bytesPerHour,
    bytesPerWindow,
    hourWindowBytes,
    hostsPerWindow,
    flowsPerWindow,
    fanout,
  };
}

/**
 * Learned volume limit: max(minBytes, mean + sigma × std, peakFactor × max).
 * @param {{ count?: number, mean?: number, m2?: number, max?: number } | null} stats
 * @param {{ minBytes: number, sigma: number, peakFactor: number }} options
 * @returns {number | null}
 */
function windowByteLimit(stats, options) {
  if (!stats || !(stats.count >= 2)) return null;
  const count = stats.count;
  const std = Math.sqrt(Math.max(0, (stats.m2 || 0) / (count - 1)));
  return Math.max(
    options.minBytes,
    (stats.mean || 0) + options.sigma * std,
    (stats.max || 0) * options.peakFactor,
  );
}

/**
 * Active-hour starts over `days`, beginning the day after learning.
 * @param {object} params
 * @param {number[]} hours
 * @param {number} days
 * @returns {number[]}
 */
function activeHours(params, hours, days) {
  const allowed = new Set(hours);
  const start = params.LEARN_DAYS * params.DAY;
  /** @type {number[]} */
  const out = [];
  for (let ts = start; ts < start + days * params.DAY; ts += HOUR) {
    if (allowed.has(hourOf(ts))) out.push(ts);
  }
  return out;
}

/**
 * One timestamp per engine window inside learned active hours.
 * @param {object} params
 * @param {number[]} hours
 * @param {number} days
 * @returns {number[]}
 */
function activeWindows(params, hours, days) {
  const allowed = new Set(hours);
  const start = params.LEARN_DAYS * params.DAY;
  const end = start + days * params.DAY;
  /** @type {number[]} */
  const out = [];
  for (let ts = start; ts < end; ts += 60_000) {
    if (allowed.has(hourOf(ts))) out.push(ts);
  }
  return out;
}

/**
 * @param {object} params
 * @param {object} envelope
 * @returns {string}
 */
function newCdnName(params, envelope) {
  const family = envelope.cdn[0] || envelope.families[0] || 'cloudfront.net';
  const rng = mulberry32(params.SEED);
  const label = 100 + Math.floor(rng() * 900);
  return `u${label}.${family}`;
}

/**
 * @param {number} index
 * @param {object} params
 * @returns {string}
 */
function scanIp(index, params) {
  const n = index + 1;
  const third = Math.floor((n - 1) / 254);
  const fourth = ((n - 1) % 254) + 1;
  return `${params.SCAN_A}.${params.SCAN_B}.${third}.${fourth}`;
}

/**
 * Bytes out for one window, at 0.9 × the learned hourly and per-window limits.
 * The flow's bytes-in matches bytes-out, so the window total is twice this.
 * @param {object} params
 * @param {object} envelope
 * @param {number} ts
 * @param {number} hourRoom
 * @param {number} goalRoom
 * @returns {number}
 */
function exfilBytes(params, envelope, ts, hourRoom, goalRoom) {
  let eventCap = Number.POSITIVE_INFINITY;
  if (envelope.bytesPerWindow != null) eventCap = Math.min(eventCap, envelope.bytesPerWindow);
  const hourCap = envelope.hourWindowBytes[hourOf(ts)];
  if (hourCap != null) eventCap = Math.min(eventCap, hourCap);
  if (!Number.isFinite(eventCap)) return Math.min(hourRoom, goalRoom);
  const perWindowOut = Math.floor((params.RATE * eventCap) / 2);
  return Math.max(0, Math.min(perWindowOut, hourRoom, goalRoom));
}

/**
 * @param {object} params
 * @param {object} envelope
 * @param {string} kind
 * @returns {{ events: object[], achieved: boolean, detail: string }}
 */
function shape(params, envelope, kind) {
  const hours = envelope.hours.length > 0 ? envelope.hours : [];
  const ja4 = envelope.ja4;
  if (kind === 'exfil') {
    const perHourOut =
      envelope.bytesPerHour == null ? 0 : Math.floor(params.RATE * envelope.bytesPerHour);
    const slots = activeWindows(params, hours, params.SPAN_DAYS);
    const name = newCdnName(params, envelope);
    /** @type {object[]} */
    const events = [];
    let sent = 0;
    let hourSent = 0;
    let hourId = null;
    if (slots.length > 0 && perHourOut > 0) {
      events.push(summary(params, slots[0], name, 1000));
      events.push(tls(params, slots[0] + 1, name, ja4));
    }
    for (const ts of slots) {
      if (sent >= params.EXFIL_BYTES) break;
      const hour = Math.floor(ts / HOUR);
      if (hour !== hourId) {
        hourId = hour;
        hourSent = 0;
      }
      if (hourSent >= perHourOut) continue;
      const bytes = exfilBytes(
        params,
        envelope,
        ts,
        perHourOut - hourSent,
        params.EXFIL_BYTES - sent,
      );
      if (bytes <= 0) continue;
      events.push(flow(params, ts + 2, params.BEACON_IP, 443, bytes, name));
      sent += bytes;
      hourSent += bytes;
    }
    return {
      events,
      achieved: sent >= params.EXFIL_BYTES,
      detail: `${sent} bytes`,
    };
  }
  if (kind === 'scan') {
    const perWindow = Math.max(
      1,
      Math.floor(
        params.RATE * Math.min(envelope.hostsPerWindow, envelope.flowsPerWindow, envelope.fanout),
      ),
    );
    const slots = activeWindows(params, hours, params.SPAN_DAYS);
    /** @type {object[]} */
    const events = [];
    let hosts = 0;
    let slot = 0;
    while (hosts < params.SCAN_HOSTS && slot < slots.length) {
      const base = slots[slot];
      const batch = Math.min(perWindow, params.SCAN_HOSTS - hosts);
      for (let i = 0; i < batch; i += 1) {
        const ts = base + i;
        events.push(flow(params, ts, scanIp(hosts, params), 443, 60, null));
        if (ja4 && i === 0)
          events.push(tls(params, ts, envelope.cdn[0] || params.VENDOR_HOST, ja4));
        hosts += 1;
      }
      slot += 1;
    }
    return { events, achieved: hosts >= params.SCAN_HOSTS, detail: `${hosts} hosts` };
  }
  if (kind === 'beacon') {
    const bytes = Math.max(1, Math.floor(params.RATE * (envelope.mean || params.LEARN_BYTES)));
    const firstHour = hours.slice().sort((a, b) => a - b)[0];
    const first = params.LEARN_DAYS * params.DAY + (firstHour == null ? 0 : firstHour) * HOUR;
    const last = first + params.BEACON_DAYS * params.DAY;
    const allowed = new Set(hours);
    const name = params.VENDOR_HOST;
    /** @type {object[]} */
    const events = [];
    for (let ts = first; ts <= last; ts += HOUR) {
      if (!allowed.has(hourOf(ts))) continue;
      events.push(flow(params, ts, params.BEACON_IP, 443, bytes, name));
      if (ja4) events.push(tls(params, ts + 1, name, ja4));
    }
    const span = events.length === 0 ? 0 : events[events.length - 1].ts - events[0].ts;
    return {
      events,
      achieved: span >= params.BEACON_DAYS * params.DAY,
      detail: `${events.length} beacons`,
    };
  }
  const range = learnedRange(envelope.ranges, params);
  const value = range.max + params.OT_OFFSET;
  const slots = activeHours(params, hours, 1);
  const ts = slots.length > 0 ? slots[0] : params.LEARN_DAYS * params.DAY;
  const outside = value > range.max || value < range.min;
  return {
    events: [writeSetpoint(params, ts, value)],
    achieved: outside && range.n >= 3,
    detail: `${params.OT_TARGET}=${value} outside ${range.min}..${range.max}`,
  };
}

/**
 * @param {any[]} ranges
 * @param {object} params
 * @returns {{ min: number, max: number, n: number }}
 */
function learnedRange(ranges, params) {
  const key = `write|${params.OT_TARGET}`;
  if (Array.isArray(ranges)) {
    for (const pair of ranges) {
      if (Array.isArray(pair) && pair[0] === key && pair[1] && typeof pair[1].max === 'number') {
        return { min: pair[1].min, max: pair[1].max, n: pair[1].n || 0 };
      }
    }
  }
  return { min: 0, max: 0, n: 0 };
}

/**
 * @param {string} severity
 * @returns {boolean}
 */
function counts(severity) {
  return (SEVERITY[severity] ?? -1) >= SEVERITY.medium;
}

/**
 * Learn the profile, read exportBaseline(), shape one goal, and score the attack engine.
 * @param {object} params
 * @param {object} baseline
 * @param {string} kind
 * @param {string} name
 * @returns {object}
 */
function runGoal(params, baseline, kind, name) {
  const envelope = readEnvelope(baseline, params);
  const attack = shape(params, envelope, kind);
  const engine = createEngine({ ...engineOptions(), alerts: true });
  engine.importBaseline(baseline, { merge: false });
  /** @type {string[]} */
  const anomalies = [];
  /** @type {string[]} */
  const alerts = [];
  engine.on('anomaly', (item) => {
    if (counts(item.severity)) anomalies.push(item.detector);
  });
  engine.on('alert', (item) => {
    alerts.push(`${item.kind}:${item.severity}`);
  });
  const start = attack.events.length > 0 ? attack.events[0].ts : 0;
  for (const event of attack.events) engine.feed(event);
  if (attack.events.length > 0) {
    engine.flush(attack.events[attack.events.length - 1].ts + 60_000);
  }
  const during = anomalies;
  const reached = attack.achieved && during.length === 0 && alerts.length === 0;
  return {
    id: kind,
    name,
    reached,
    achieved: attack.achieved,
    detail: attack.detail,
    anomalies: [...new Set(during)],
    alerts: alerts.length,
    alertKinds: [...new Set(alerts)],
    measured: true,
    start,
  };
}

/**
 * @param {number} bytes
 * @returns {string}
 */
function megabytes(bytes) {
  return String(bytes / (1024 * 1024));
}

/**
 * @param {number} n
 * @returns {string}
 */
function grouped(n) {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * @param {object} params
 * @returns {{ id: string, name: string }[]}
 */
function goalList(params) {
  return [
    {
      id: 'exfil',
      name: `exfiltrate ${megabytes(params.EXFIL_BYTES)} MB in ${params.SPAN_DAYS} days`,
    },
    {
      id: 'scan',
      name: `scan ${grouped(params.SCAN_HOSTS)} LAN or WAN hosts in ${params.SPAN_DAYS} days`,
    },
    { id: 'beacon', name: `keep a C2 beacon for ${params.BEACON_DAYS} days` },
    { id: 'ot', name: 'write one OT setpoint outside its learned range' },
  ];
}

/**
 * @param {object} report
 * @param {object} params
 * @returns {string}
 */
function renderAdversary(report, params) {
  const lines = [
    '# Adaptive adversary',
    '',
    'White-box. The generator read exportBaseline() of the target device and shaped each goal inside the learned envelope: destinations among learned families or new names in learned CDNs, rates at ' +
      `${params.RATE} times each learned threshold, timing inside learned active hours, and the learned JA4 when one exists.`,
    '',
    'No threshold was tuned. Detector defaults were not changed.',
    '',
    'alerts: measured on the attack engine with alerts true. A goal is reached only when the attack lands and that run emits no alert and no anomaly at medium or above.',
    '',
    '## Goals',
    '',
  ];
  for (const goal of report.goals) {
    const status = goal.reached ? 'reached (white-box blind spot)' : 'not reached';
    const extra = goal.anomalies.length > 0 ? ` (${goal.anomalies.join(', ')})` : '';
    const kinds =
      goal.alertKinds && goal.alertKinds.length > 0 ? ` [${goal.alertKinds.join(', ')}]` : '';
    lines.push(`- ${goal.name}: ${status}${extra}; alerts ${goal.alerts}${kinds}`);
  }
  lines.push('');
  lines.push('Reached goals are published as white-box blind spots.');
  lines.push('');
  return lines.join('\n');
}

/**
 * Run the four goals and write `eval/results/adversary.md`.
 * @param {{ outPath?: string, params?: object }} [opts]
 * @returns {object}
 */
function runAdversary(opts = {}) {
  const params = opts.params || published;
  const learner = createEngine(engineOptions());
  for (const event of learningEvents(params)) learner.feed(event);
  learner.lock(params.DEVICE);
  const baseline = learner.exportBaseline({ createdAt: params.SEED, devices: [params.DEVICE] });
  const envelope = readEnvelope(baseline, params);
  const goals = goalList(params).map((goal) => runGoal(params, baseline, goal.id, goal.name));
  const text = renderAdversary({ goals }, params);
  const file = opts.outPath || path.join(__dirname, '..', 'results', 'adversary.md');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return {
    file,
    goals,
    families: envelope.families,
    hours: envelope.hours,
    ja4: envelope.ja4,
    cdn: envelope.cdn,
  };
}

module.exports = { runAdversary, learningEvents, readEnvelope, goalList };
