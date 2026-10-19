'use strict';

const { createEngine, SEVERITY } = require('iotwarden');

const WINDOW = 60_000;
const HOUR = 3600e3;
const LEARNED = '45.2.1.10';

/**
 * Synthetic evasion suite from SPEC C6.2. Thresholds are not modified.
 * Every attack uses a port, a protocol, and a /24 the victim learned.
 * @returns {{ id: string, fired: boolean, detectors: string[] }[]}
 */
function runEvasion() {
  return [slowScan(), jitteredBeacon(), underLimitExfil(), splitFlood()];
}

/**
 * One new host per window, on learned ports 80 and 443, inside the learned /24.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function slowScan() {
  /** @type {any[]} */
  const events = [
    flow('scan', 0, LEARNED, 443, { proto: 'tcp', bytesOut: 60, pktsOut: 1 }),
    flow('scan', 1_000, LEARNED, 80, { proto: 'tcp', bytesOut: 60, pktsOut: 1 }),
  ];
  for (let i = 0; i < 30; i += 1) {
    const port = i % 2 === 0 ? 80 : 443;
    events.push(
      flow('scan', WINDOW + i * WINDOW, `45.2.1.${11 + i}`, port, {
        proto: 'tcp',
        bytesOut: 60,
        pktsOut: 1,
      }),
    );
  }
  return report('slow-scan', events, 2);
}

/**
 * 40% jitter around a 60 s gap, to the host whose cadence was learned.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function jitteredBeacon() {
  /** @type {any[]} */
  const events = [];
  for (let i = 0; i < 5; i += 1) {
    events.push(
      flow('beacon', i * WINDOW, LEARNED, 443, { proto: 'tcp', bytesOut: 120, pktsOut: 1 }),
    );
  }
  let ts = 5 * WINDOW;
  for (let i = 0; i < 25; i += 1) {
    const jitter = i % 2 === 0 ? 0.4 : -0.4;
    ts += Math.round(WINDOW * (1 + jitter));
    events.push(flow('beacon', ts, LEARNED, 443, { proto: 'tcp', bytesOut: 120, pktsOut: 1 }));
  }
  return report('beacon-jitter-40', events, 5);
}

/**
 * One closed hour at 0.9 × the slow-exfil limit max(5 × mean, 1 MB), to the learned host.
 * Seven learning hours close six 1,000-byte samples, which is `minSamples`.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function underLimitExfil() {
  const mean = 1000;
  const limit = Math.max(5 * mean, 1_000_000);
  /** @type {any[]} */
  const events = [];
  for (let hour = 0; hour < 7; hour += 1) {
    events.push(
      flow('exfil', hour * HOUR, LEARNED, 443, { proto: 'tcp', bytesOut: mean, pktsOut: 1 }),
    );
  }
  events.push(
    flow('exfil', 7 * HOUR, LEARNED, 443, {
      proto: 'tcp',
      bytesOut: Math.round(0.9 * limit),
      pktsOut: 1,
    }),
  );
  events.push(flow('exfil', 8 * HOUR, LEARNED, 443, { proto: 'tcp', bytesOut: mean, pktsOut: 1 }));
  return report('exfil-0.9-limit', events, 7);
}

/**
 * The single-destination flood threshold split evenly across 10 hosts in the learned /24.
 * UDP port 80 was learned. Each flow is one-way.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function splitFlood() {
  /** @type {any[]} */
  const events = [flow('flood', 0, LEARNED, 80, { proto: 'udp', bytesOut: 60, pktsOut: 1 })];
  for (let i = 0; i < 10; i += 1) {
    events.push(
      flow('flood', WINDOW, `45.2.1.${i + 1}`, 80, {
        proto: 'udp',
        bytesOut: 200_000_000 / 10,
        pktsOut: 50_000 / 10,
        bytesIn: 0,
      }),
    );
  }
  return report('flood-10-destinations', events, 1);
}

/**
 * @param {string} id
 * @param {any[]} events
 * @param {number} learnCount
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function report(id, events, learnCount) {
  const engine = createEngine({ learnMs: 1e14, tiers: ['T1'], evidence: false });
  /** @type {any[]} */
  const hits = [];
  const note = (item) => {
    if ((SEVERITY[item.severity] ?? -1) >= SEVERITY.medium) hits.push(item.detector);
  };
  engine.on('anomaly', note);
  engine.on('shadow-anomaly', note);
  for (let i = 0; i < learnCount; i += 1) engine.feed(events[i]);
  engine.lock(events[0].device);
  for (let i = learnCount; i < events.length; i += 1) engine.feed(events[i]);
  const last = events[events.length - 1];
  engine.flush(last.ts + WINDOW);
  return { id, fired: hits.length > 0, detectors: [...new Set(hits)] };
}

/**
 * @param {string} device
 * @param {number} ts
 * @param {string} dstIp
 * @param {number} dstPort
 * @param {{ proto: string, bytesOut: number, pktsOut: number, bytesIn?: number }} extra
 */
function flow(device, ts, dstIp, dstPort, extra) {
  return {
    type: 'flow',
    device,
    ts,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp,
    dstPort,
    proto: extra.proto,
    direction: 'out',
    bytesOut: extra.bytesOut,
    bytesIn: extra.bytesIn || 0,
    pktsOut: extra.pktsOut,
    pktsIn: 0,
    durationMs: 10,
  };
}

/**
 * @param {{ id: string, fired: boolean, detectors: string[] }[]} scenarios
 * @returns {string}
 */
function renderEvasion(scenarios) {
  const lines = [
    '# Evasion',
    '',
    'Synthetic known blind spots. Thresholds were not tuned against this suite.',
    '',
    'Attack intervals: contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes.',
    '',
    'T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised.',
    '',
    'Learning span: the benign prefix of each scenario, then lock.',
    '',
    'Malicious-label share inside the learning prefix: 0.',
    '',
  ];
  for (const scenario of scenarios) {
    const who = scenario.detectors.length > 0 ? scenario.detectors.join(', ') : 'none';
    const spot = scenario.fired ? 'fired' : 'blind spot';
    lines.push(`- ${scenario.id}: ${spot} (${who})`);
  }
  lines.push('');
  lines.push(
    'Shadow rows measured on this suite. A miss stays a blind spot. The holdout is separate.',
  );
  lines.push('');
  const watch = [
    ['slow-scan', 'slow-scan'],
    ['beacon-jitter-40', 'jitter-beacon'],
    ['exfil-0.9-limit', 'multi-horizon-exfil'],
  ];
  for (const [scenarioId, detectorId] of watch) {
    const scenario = scenarios.find((row) => row.id === scenarioId);
    const fired = scenario && scenario.detectors.includes(detectorId);
    lines.push(`- ${detectorId}: ${fired ? 'fired' : 'blind spot'}`);
  }
  lines.push('');
  return lines.join('\n');
}

module.exports = { runEvasion, renderEvasion };
