'use strict';

const { createEngine, SEVERITY } = require('iotwarden');

const WINDOW = 60_000;
const HOUR = 3600e3;

/**
 * Synthetic evasion suite from SPEC C6.2. Thresholds are not modified.
 * @returns {{ id: string, fired: boolean, detectors: string[] }[]}
 */
function runEvasion() {
  return [slowScan(), jitteredBeacon(), underLimitExfil(), splitFlood()];
}

/**
 * One new host per window, after a single benign flow and lock.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function slowScan() {
  /** @type {any[]} */
  const events = [flow('scan', 0, '1.2.3.4', 443, { bytesOut: 60, pktsOut: 1 })];
  for (let i = 0; i < 30; i += 1) {
    events.push(
      flow('scan', WINDOW + i * WINDOW, `45.1.1.${i + 1}`, 23, { bytesOut: 60, pktsOut: 1 }),
    );
  }
  return report('slow-scan', events, 1);
}

/**
 * Beacon gaps alternate ±40% around 60 s, to a destination that was not learned.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function jitteredBeacon() {
  /** @type {any[]} */
  const events = [flow('beacon', 0, '1.2.3.4', 443, { bytesOut: 100, pktsOut: 1 })];
  let ts = WINDOW;
  for (let i = 0; i < 25; i += 1) {
    const jitter = i % 2 === 0 ? 0.4 : -0.4;
    ts += Math.round(WINDOW * (1 + jitter));
    events.push(flow('beacon', ts, '9.9.9.9', 443, { bytesOut: 120, pktsOut: 1 }));
  }
  return report('beacon-jitter-40', events, 1);
}

/**
 * One closed hour at 0.9 × the slow-exfil limit max(5 × mean, 1 MB).
 * Seven learning hours close six 1,000-byte samples, which is `minSamples`.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function underLimitExfil() {
  const mean = 1000;
  const limit = Math.max(5 * mean, 1_000_000);
  /** @type {any[]} */
  const events = [];
  for (let hour = 0; hour < 7; hour += 1) {
    events.push(flow('exfil', hour * HOUR, '1.2.3.4', 443, { bytesOut: mean, pktsOut: 1 }));
  }
  events.push(
    flow('exfil', 7 * HOUR, '1.2.3.4', 443, { bytesOut: Math.round(0.9 * limit), pktsOut: 1 }),
  );
  events.push(flow('exfil', 8 * HOUR, '1.2.3.4', 443, { bytesOut: mean, pktsOut: 1 }));
  return report('exfil-0.9-limit', events, 7);
}

/**
 * The single-destination flood threshold split evenly across 10 destinations.
 * @returns {{ id: string, fired: boolean, detectors: string[] }}
 */
function splitFlood() {
  /** @type {any[]} */
  const events = [flow('flood', 0, '1.2.3.4', 443, { bytesOut: 60, pktsOut: 1 })];
  for (let i = 0; i < 10; i += 1) {
    events.push(
      flow('flood', WINDOW, `45.2.1.${i + 1}`, 80, {
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
  engine.on('anomaly', (item) => {
    if ((SEVERITY[item.severity] ?? -1) >= SEVERITY.medium) {
      hits.push(item.detector);
    }
  });
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
 * @param {{ bytesOut: number, pktsOut: number, bytesIn?: number }} extra
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
    proto: 'tcp',
    direction: 'out',
    bytesOut: extra.bytesOut,
    bytesIn: extra.bytesIn || 0,
    pktsOut: extra.pktsOut,
    pktsIn: 0,
    durationMs: 10,
  };
}

module.exports = { runEvasion };
