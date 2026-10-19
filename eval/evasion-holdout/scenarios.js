'use strict';

const { mulberry32, range } = require('../../test/fixtures/prng.js');

/** Different from eval/evasion, which has no seed and uses 45.2.1.0/24. */
const SEED = 20261018;
const HOUR = 3600e3;
const GAP_MS = 300_000;
const JITTER = 0.45;
const PAIRS_PER_HOUR = 2;
const SCAN_HOURS = 30;
const BEACON_MS = 6 * HOUR;
const EXFIL_HOURS = 20;
const EXFIL_FACTOR = 0.85;
const LEARN_MEAN = 2500;
const SLOW_EXFIL_FLOOR = 1_000_000;
const LEARNED_IP = '47.8.3.10';
const SCAN_BASE = 47;
const BEACON_IP = '47.8.9.20';

/**
 * Hourly upload that is 0.85 × the slow-exfil limit max(5 × learned mean, 1 MB).
 * The published suite uses 0.9 × that limit for one hour and a 1,000-byte mean.
 * @returns {number}
 */
function exfilBytesPerHour() {
  const limit = Math.max(5 * LEARN_MEAN, SLOW_EXFIL_FLOOR);
  return Math.round(EXFIL_FACTOR * limit);
}

/**
 * @param {string} device
 * @param {number} ts
 * @param {string} dstIp
 * @param {number} dstPort
 * @param {number} bytesOut
 */
function flow(device, ts, dstIp, dstPort, bytesOut) {
  return {
    type: 'flow',
    device,
    ts,
    srcIp: '10.1.0.8',
    srcPort: 41000,
    dstIp,
    dstPort,
    proto: 'tcp',
    direction: 'out',
    bytesOut,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 20,
  };
}

/**
 * Two new host:port pairs per hour for 30 hours, after one learned host.
 * Ports are 8080 and 9443. Addresses are 47.8.3.0/24, not 45.2.1.0/24.
 * @returns {{ id: string, learnCount: number, events: object[] }}
 */
function slowScan() {
  /** @type {object[]} */
  const events = [];
  for (let hour = 0; hour < 2; hour += 1) {
    events.push(flow('hold-scan', hour * HOUR, LEARNED_IP, 443, 80));
  }
  const learnCount = events.length;
  for (let hour = 0; hour < SCAN_HOURS; hour += 1) {
    for (let pair = 0; pair < PAIRS_PER_HOUR; pair += 1) {
      const n = hour * PAIRS_PER_HOUR + pair;
      const host = 11 + (n % 240);
      const port = pair === 0 ? 8080 : 9443;
      events.push(
        flow('hold-scan', (2 + hour) * HOUR + pair * 1000, `${SCAN_BASE}.8.3.${host}`, port, 60),
      );
    }
  }
  return { id: 'holdout-slow-scan', learnCount, events };
}

/**
 * A beacon every 300 s ± 45% for 6 hours, to an address that was not learned.
 * Jitter comes from seed 20261018. The published suite uses a fixed ±40% on a 60 s gap.
 * @returns {{ id: string, learnCount: number, events: object[] }}
 */
function jitteredBeacon() {
  const rng = mulberry32(SEED);
  /** @type {object[]} */
  const events = [flow('hold-beacon', 0, LEARNED_IP, 443, 100)];
  const start = HOUR;
  let ts = start;
  const end = start + BEACON_MS;
  while (ts < end) {
    events.push(flow('hold-beacon', ts, BEACON_IP, 443, 120));
    const jitter = range(rng, -JITTER, JITTER);
    ts += Math.round(GAP_MS * (1 + jitter));
  }
  return { id: 'holdout-beacon-45', learnCount: 1, events };
}

/**
 * Twenty hours at 0.85 × the slow-exfil hourly limit, after six learning hours.
 * @returns {{ id: string, learnCount: number, events: object[] }}
 */
function underLimitExfil() {
  const bytes = exfilBytesPerHour();
  /** @type {object[]} */
  const events = [];
  for (let hour = 0; hour < 6; hour += 1) {
    events.push(flow('hold-exfil', hour * HOUR, LEARNED_IP, 443, LEARN_MEAN));
  }
  const learnCount = events.length;
  for (let hour = 0; hour < EXFIL_HOURS; hour += 1) {
    events.push(flow('hold-exfil', (6 + hour) * HOUR, LEARNED_IP, 443, bytes));
  }
  return { id: 'holdout-exfil-0.85', learnCount, events };
}

/**
 * The three holdout shapes. No detector reads this module.
 * @returns {{ id: string, learnCount: number, events: object[] }[]}
 */
function scenarios() {
  return [slowScan(), jitteredBeacon(), underLimitExfil()];
}

module.exports = {
  SEED,
  PAIRS_PER_HOUR,
  SCAN_HOURS,
  GAP_MS,
  JITTER,
  BEACON_MS,
  EXFIL_HOURS,
  EXFIL_FACTOR,
  LEARN_MEAN,
  exfilBytesPerHour,
  scenarios,
};
