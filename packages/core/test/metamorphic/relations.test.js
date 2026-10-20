'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY } = require('../../../../test/fixtures/clock');
const { mulberry32 } = require('../../../../test/fixtures/prng');

const WEEK = 7 * DAY;
const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const SHADOW = ['exploit-probe-http', 'young-domain', 'ttl-anomaly'];
const SET_DETECTORS = [
  'new-destination',
  'new-port',
  'new-protocol',
  'new-domain-family',
  'new-client-fingerprint',
  'cert-change',
];
const THRESHOLD = [
  'horizontal-scan',
  'vertical-scan',
  'fan-out',
  'volume-spike',
  'volume-spike-hourly',
  'packet-flood',
  'egress-flood',
  'upload-ratio-shift',
  'failed-connection-ratio',
  'nxdomain-burst',
  'connection-churn',
  'beacon-change',
  'long-connection',
  'slow-exfil',
];

/**
 * @param {any} opts
 * @param {any[]} steps
 * @param {number} [flushAt]
 */
function play(opts, steps, flushAt) {
  const engine = createEngine({ shadow: true, ...opts });
  /** @type {any[]} */
  const anomalies = [];
  engine.on('anomaly', (item) => anomalies.push(item));
  for (const step of steps) {
    if (step && step.op === 'class') engine.setDeviceClass(step.device, step.classId);
    else if (step && step.op === 'indicators') engine.loadIndicators(step.list);
    else if (step && step.op === 'lock') engine.lock(step.device);
    else engine.feed(step);
  }
  if (flushAt != null) engine.flush(flushAt);
  return { engine, anomalies };
}

/**
 * @param {any} item
 * @returns {string}
 */
function view(item) {
  return JSON.stringify({
    detector: item.detector,
    device: item.device,
    ts: item.ts,
    severity: item.severity,
    category: item.category,
    actual: item.actual,
    expected: item.expected,
    data: item.data,
    hardRule: item.hardRule,
  });
}

/**
 * @param {any[]} anomalies
 * @returns {string[]}
 */
function views(anomalies) {
  return anomalies.map(view).sort();
}

/**
 * Events in timestamp order. A step that is not an event stays immediately before the next event.
 * @param {any[]} steps
 * @returns {any[]}
 */
function sortedStream(steps) {
  /** @type {{ step: any, ts: number }[]} */
  const ops = [];
  /** @type {any[]} */
  const events = [];
  /** @type {any[]} */
  let pending = [];
  for (const step of steps) {
    if (step && step.op) pending.push(step);
    else {
      for (const op of pending) ops.push({ step: op, ts: step.ts });
      pending = [];
      events.push(step);
    }
  }
  events.sort((a, b) => a.ts - b.ts);
  /** @type {any[]} */
  const out = [];
  let index = 0;
  for (const event of events) {
    while (index < ops.length && ops[index].ts <= event.ts) {
      out.push(ops[index].step);
      index += 1;
    }
    out.push(event);
  }
  while (index < ops.length) {
    out.push(ops[index].step);
    index += 1;
  }
  out.push(...pending);
  return out;
}

/**
 * @returns {{ name: string, opts: any, steps: any[], flushAt?: number }[]}
 */
function cases() {
  /** @type {{ name: string, opts: any, steps: any[], flushAt?: number }[]} */
  const out = [];
  for (const profile of CLASS_NAMES) {
    const events = simulate({
      profile,
      days: 14,
      seed: 1,
      startTs: T0,
      rich: true,
      discovery: true,
    });
    out.push({
      name: `benign:${profile}`,
      opts: { learnMs: 7 * DAY, tiers: TIERS },
      steps: [{ op: 'class', device: events[0].device, classId: profile }, ...events],
      flushAt: T0 + 14 * DAY,
    });
  }
  out.push(mirai(), badbox(), kimwolf(), mitm(), bms(), flood(), smartTv());
  return out;
}

function mirai() {
  /** @type {any[]} */
  const steps = [];
  for (let i = 1; i <= 12; i++) {
    steps.push({
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
  steps.push({
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
  return { name: 'replay:mirai', opts: { learnMs: 86_400_000, tiers: ['T0', 'T1'] }, steps };
}

function badbox() {
  const names = [
    'www.amazon.com',
    'www.ebay.com',
    'www.facebook.com',
    'www.tiktok.com',
    'www.ticketmaster.com',
    'www.eventbrite.com',
  ];
  return {
    name: 'replay:badbox',
    opts: { learnMs: 7 * DAY, tiers: ['T0', 'T1', 'T2'] },
    steps: [
      { op: 'class', device: 'box', classId: 'tv-box' },
      ...names.map((dstName, index) => ({
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
      })),
    ],
  };
}

function kimwolf() {
  const names = [
    'www.amazon.com',
    'www.walmart.com',
    'www.facebook.com',
    'www.reddit.com',
    'www.ticketmaster.com',
    'www.stubhub.com',
  ];
  /** @type {any[]} */
  const steps = names.map((dstName, index) => ({
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
  }));
  for (let i = 1; i <= 12; i++) {
    steps.push({
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
  steps.push({
    type: 'dns',
    device: 'box',
    ts: 3000,
    qname: 'mainnet.infura.io',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  return {
    name: 'replay:kimwolf',
    opts: { learnMs: 86_400_000, tiers: ['T0', 'T1', 'T2'] },
    steps,
  };
}

function mitm() {
  return {
    name: 'replay:mitm',
    opts: { learnMs: 86_400_000, tiers: ['T0', 'T3'] },
    steps: [
      {
        type: 'tls',
        device: 'cam',
        ts: 1000,
        dstIp: '1.2.3.4',
        dstPort: 443,
        sni: 'video.vendor.com',
        cert: { issuer: 'Vendor CA' },
      },
      { op: 'lock', device: 'cam' },
      {
        type: 'tls',
        device: 'cam',
        ts: 5000,
        dstIp: '1.2.3.4',
        dstPort: 443,
        sni: 'video.vendor.com',
        cert: { issuer: 'Unexpected CA' },
      },
    ],
  };
}

/**
 * @param {number} ts
 * @param {string} peer
 * @param {string} op
 * @param {string} target
 * @param {number | string} value
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

function bms() {
  return {
    name: 'replay:bms',
    opts: { learnMs: 86_400_000, tiers: ['T0', 'T5'] },
    steps: [
      app(1020, '10.0.0.2', 'WriteProperty', 'setpoint', 20),
      app(1021, '10.0.0.2', 'WriteProperty', 'setpoint', 21),
      app(1022, '10.0.0.2', 'WriteProperty', 'setpoint', 22),
      { op: 'lock', device: 'ahu-1' },
      app(5000, '10.0.0.9', 'WriteProperty', 'setpoint', 21),
      app(6000, '10.0.0.2', 'WriteProperty', 'setpoint', 40),
      app(7000, '10.0.0.9', 'DeviceCommunicationControl', 'device'),
    ],
  };
}

function flood() {
  return {
    name: 'replay:flood',
    opts: { learnMs: 86_400_000, tiers: ['T1'] },
    steps: [
      {
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
      },
    ],
  };
}

function smartTv() {
  return {
    name: 'replay:smart-tv',
    opts: { learnMs: 0, tiers: ['T1', 'T2'] },
    steps: [
      { op: 'class', device: 'tv', classId: 'smart-tv' },
      {
        op: 'indicators',
        list: [{ value: 'sdk.proxy.example', type: 'proxy-sdk', source: 'lab', confidence: 0.9 }],
      },
      {
        type: 'dns',
        device: 'tv',
        ts: 1_000,
        qname: 'sdk.proxy.example',
        qtype: 'A',
        rcode: 'NOERROR',
        resolver: '10.0.0.1',
        answers: [{ type: 'A', value: '1.2.3.9', ttl: 30 }],
      },
      {
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
      },
      {
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
      },
    ],
  };
}

/**
 * @param {any[]} steps
 * @param {(event: any) => any} map
 * @returns {any[]}
 */
function mapEvents(steps, map) {
  return steps.map((step) => (step && step.op ? step : map(step)));
}

/**
 * @param {any[]} steps
 * @param {number} delta
 */
function shift(steps, delta) {
  return steps.map((step) => (step && step.ts != null ? { ...step, ts: step.ts + delta } : step));
}

/**
 * @param {string} text
 * @param {Record<string, string>} inverse
 */
function rewrite(text, inverse) {
  let out = text;
  const keys = Object.keys(inverse).sort((a, b) => b.length - a.length);
  for (const key of keys) out = out.split(key).join(inverse[key]);
  return out;
}

/**
 * @param {any} value
 * @param {Record<string, string>} inverse
 * @returns {any}
 */
function rewriteValue(value, inverse) {
  if (typeof value === 'string') return rewrite(value, inverse);
  if (Array.isArray(value)) return value.map((item) => rewriteValue(item, inverse));
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const [key, item] of Object.entries(value)) out[key] = rewriteValue(item, inverse);
    return out;
  }
  return value;
}

test('time shift keeps anomalies and moves their timestamps by whole weeks', () => {
  for (const item of cases()) {
    const base = views(play(item.opts, item.steps, item.flushAt).anomalies);
    const moved = play(
      item.opts,
      shift(item.steps, WEEK),
      item.flushAt == null ? undefined : item.flushAt + WEEK,
    );
    const back = views(moved.anomalies.map((row) => ({ ...row, ts: row.ts - WEEK })));
    assert.deepStrictEqual(back, base, item.name);
  }
});

test('device rename keeps anomalies except fingerprints', () => {
  for (const item of cases()) {
    /** @type {string[]} */
    const ids = [];
    for (const step of item.steps) {
      if (step && step.device && !ids.includes(step.device)) ids.push(step.device);
    }
    /** @type {Record<string, string>} */
    const forward = {};
    /** @type {Record<string, string>} */
    const inverse = {};
    ids.forEach((id, index) => {
      forward[id] = `dev-${index}`;
      inverse[`dev-${index}`] = id;
    });
    const renamedSteps = item.steps.map((step) => {
      if (!step || !step.device) return step;
      const device = forward[step.device] || step.device;
      if (step.op) return { ...step, device };
      return { ...step, device };
    });
    const base = views(play(item.opts, item.steps, item.flushAt).anomalies);
    const got = play(item.opts, renamedSteps, item.flushAt).anomalies.map((row) =>
      rewriteValue(row, inverse),
    );
    assert.deepStrictEqual(views(got), base, item.name);
  }
});

test('a checkpoint in the middle matches an uninterrupted run', () => {
  const rng = mulberry32(1);
  for (const item of cases()) {
    const feeds = item.steps.filter((step) => !step.op);
    if (feeds.length < 2) continue;
    const cut = 1 + Math.floor(rng() * (feeds.length - 1));
    let seen = 0;
    /** @type {any[]} */
    const head = [];
    /** @type {any[]} */
    const tail = [];
    for (const step of item.steps) {
      if (step && step.op) {
        (seen < cut ? head : tail).push(step);
        continue;
      }
      (seen < cut ? head : tail).push(step);
      seen += 1;
    }
    const base = views(play(item.opts, item.steps, item.flushAt).anomalies);
    const first = play(item.opts, head);
    const saved = first.engine.checkpoint({ createdAt: 1 });
    const second = createEngine({ shadow: true, ...item.opts });
    /** @type {any[]} */
    const rest = [];
    second.on('anomaly', (row) => rest.push(row));
    second.restore(saved);
    for (const step of tail) {
      if (step && step.op === 'class') second.setDeviceClass(step.device, step.classId);
      else if (step && step.op === 'indicators') second.loadIndicators(step.list);
      else if (step && step.op === 'lock') second.lock(step.device);
      else second.feed(step);
    }
    if (item.flushAt != null) second.flush(item.flushAt);
    assert.deepStrictEqual(views(first.anomalies.concat(rest)), base, `${item.name} cut ${cut}`);
  }
});

test('shuffling inside 5000 ms does not change the anomaly multiset', () => {
  const rng = mulberry32(1);
  for (const item of cases()) {
    const opts = { ...item.opts, reorderMs: 5000 };
    /** @type {Map<number, any[]>} */
    const groups = new Map();
    /** @type {any[]} */
    const order = [];
    for (const step of item.steps) {
      if (step && step.op) {
        order.push(step);
        continue;
      }
      const bucket = Math.floor(step.ts / 5000) * 5000;
      const list = groups.get(bucket) || [];
      list.push(step);
      if (list.length === 1) order.push(bucket);
      groups.set(bucket, list);
    }
    /** @type {any[]} */
    const shuffled = [];
    for (const entry of order) {
      if (typeof entry !== 'number') {
        shuffled.push(entry);
        continue;
      }
      const list = groups.get(entry);
      /** @type {any[][]} */
      const tied = [];
      /** @type {Map<number, any[]>} */
      const byTs = new Map();
      for (const event of list) {
        let group = byTs.get(event.ts);
        if (!group) {
          group = [];
          byTs.set(event.ts, group);
          tied.push(group);
        }
        group.push(event);
      }
      for (let i = tied.length - 1; i > 0; i--) {
        const j = Math.floor(rng() * (i + 1));
        const swap = tied[i];
        tied[i] = tied[j];
        tied[j] = swap;
      }
      for (const group of tied) shuffled.push(...group);
    }
    const got = views(play(opts, shuffled, item.flushAt).anomalies);
    const expected = views(play(opts, sortedStream(item.steps), item.flushAt).anomalies);
    assert.deepStrictEqual(got, expected, item.name);
  }
});

test('doubling attack magnitude keeps every threshold detector that fired', () => {
  /** @type {Set<string>} */
  const checked = new Set();
  for (const item of cases()) {
    if (!item.name.startsWith('replay:')) continue;
    const before = new Set(
      play(item.opts, item.steps, item.flushAt).anomalies.map((row) => row.detector),
    );
    const bigger = mapEvents(item.steps, (event) => {
      const copy = { ...event };
      for (const key of ['bytes', 'bytesOut', 'bytesIn', 'pktsOut', 'pktsIn']) {
        if (typeof copy[key] === 'number') copy[key] *= 2;
      }
      return copy;
    });
    if (item.name === 'replay:mirai' || item.name === 'replay:kimwolf') {
      const extra = item.steps
        .filter((step) => step && step.dstIp && String(step.dstPort) !== '443')
        .map((step) => ({
          ...step,
          dstIp: step.dstIp.replace(/(\d+)$/, (octet) => String(Number(octet) + 20)),
          srcPort: step.srcPort + 100,
          bytesOut: (step.bytesOut || 0) * 2,
          pktsOut: (step.pktsOut || 0) * 2,
        }));
      bigger.push(...extra);
    }
    const after = new Set(
      play(item.opts, bigger, item.flushAt).anomalies.map((row) => row.detector),
    );
    for (const id of before) {
      if (!THRESHOLD.includes(id)) continue;
      checked.add(id);
      assert.ok(after.has(id), `${item.name} lost ${id}`);
    }
  }
  console.log(`threshold detectors checked: ${[...checked].sort().join(', ')}`);
});

test('duplicating benign events does not add set-membership anomalies', () => {
  for (const item of cases()) {
    if (!item.name.startsWith('benign:')) continue;
    const before = play(item.opts, item.steps, item.flushAt).anomalies.filter((row) =>
      SET_DETECTORS.includes(row.detector),
    );
    /** @type {any[]} */
    const doubled = [];
    for (const step of item.steps) {
      doubled.push(step);
      if (step && !step.op) doubled.push({ ...step });
    }
    const after = play(item.opts, doubled, item.flushAt).anomalies.filter((row) =>
      SET_DETECTORS.includes(row.detector),
    );
    assert.deepStrictEqual(views(after), views(before), item.name);
  }
});

test('shadow detectors do not change the live stream or the live baseline', () => {
  for (const item of cases()) {
    const on = play(item.opts, item.steps, item.flushAt);
    /** @type {Record<string, { enabled: boolean }>} */
    const offDetectors = {};
    for (const id of SHADOW) offDetectors[id] = { enabled: false };
    const off = play({ ...item.opts, detectors: offDetectors }, item.steps, item.flushAt);
    assert.deepStrictEqual(views(on.anomalies), views(off.anomalies), item.name);
    const left = on.engine.exportBaseline({ createdAt: 1 });
    const right = off.engine.exportBaseline({ createdAt: 1 });
    for (const device of Object.values(left.devices)) {
      for (const id of SHADOW) delete device.detectors[id];
    }
    for (const device of Object.values(right.devices)) {
      for (const id of SHADOW) delete device.detectors[id];
    }
    assert.deepStrictEqual(left, right, item.name);
  }
});

test('the first suppress entry removes one replay anomaly and leaves the rest', () => {
  for (const spec of [mirai(), kimwolf()]) {
    const first = play(spec.opts, spec.steps, spec.flushAt);
    const head = play(spec.opts, spec.steps.slice(0, 1), spec.flushAt);
    const early = new Set(views(head.anomalies));
    const preferred = ['horizontal-scan', 'adb-exposure', 'packet-flood', 'new-protocol'];
    const chosen = first.anomalies.find((item) => {
      if (!preferred.includes(item.detector) || early.has(view(item))) return false;
      const row = first.engine.explain(item.id);
      return row && row.suppressWith[0] && row.suppressWith[0].method === 'suppress';
    });
    assert.ok(chosen, spec.name);
    const entry = first.engine.explain(chosen.id).suppressWith[0];
    const second = createEngine({ shadow: true, ...spec.opts });
    /** @type {any[]} */
    const anomalies = [];
    second.on('anomaly', (item) => anomalies.push(item));
    let armed = false;
    for (const step of spec.steps) {
      if (step && step.op === 'class') second.setDeviceClass(step.device, step.classId);
      else if (step && step.op === 'lock') second.lock(step.device);
      else if (step && step.op === 'indicators') second.loadIndicators(step.list);
      else if (!armed) {
        second.feed(step);
        second.suppress(entry.args[0], entry.args[1], entry.args[2] || {});
        armed = true;
      } else second.feed(step);
    }
    if (spec.flushAt != null) second.flush(spec.flushAt);
    const expected = views(first.anomalies);
    const index = expected.indexOf(view(chosen));
    assert.ok(index >= 0, spec.name);
    expected.splice(index, 1);
    assert.deepStrictEqual(views(anomalies), expected, spec.name);
  }
});
