'use strict';

const { HubvikError } = require('../errors');

const { TIERS } = require('./constants');
const ATTACK = require('../data/attack-map.json');
const SCENARIOS = require('../data/selftest.json');

const SCENARIO_CAP = 16;
const EVENT_CAP = 10_000;

/**
 * Which techniques the logs already fed can support. This does not detect.
 * @this {any}
 * @param {number} [now]
 */
function coverage(now) {
  const at = typeof now === 'number' && Number.isFinite(now) ? now : this.watermark || 0;
  const enabled = new Set(this.opts.tiers);
  const seen = this.tierSeen || {};
  const counts = this.tierCounts || {};
  /** @type {Record<string, { enabled: boolean, eventsSeen: number, lastTs: number | null, silent: boolean }>} */
  const tiers = Object.create(null);
  for (const tier of TIERS) {
    const last = typeof seen[tier] === 'number' ? seen[tier] : null;
    const on = enabled.has(tier);
    tiers[tier] = {
      enabled: on,
      eventsSeen: counts[tier] || 0,
      lastTs: last,
      silent: on && (last == null || at - last >= this.opts.tierSilentMs),
    };
  }
  /** @type {Record<string, { active: boolean, reason: string | null, mode: 'live' | 'shadow' }>} */
  const detectors = Object.create(null);
  for (const det of this.registry) {
    const status = this.detectorStatus[det.id] || { active: false, reason: null };
    detectors[det.id] = {
      active: Boolean(status.active),
      reason: status.reason ?? null,
      mode: detectorMode(this, det),
    };
  }
  /** @type {Record<string, string[]>} */
  const byTechnique = Object.create(null);
  for (const [id, list] of Object.entries(ATTACK)) {
    for (const technique of list) {
      if (!byTechnique[technique]) byTechnique[technique] = [];
      byTechnique[technique].push(id);
    }
  }
  /** @type {Record<string, { detectors: string[], coveredLive: boolean, coveredShadow: boolean, blockedBy: string | null }>} */
  const techniques = Object.create(null);
  let live = 0;
  let shadowOnly = 0;
  let blind = 0;
  for (const technique of Object.keys(byTechnique).sort()) {
    const ids = byTechnique[technique].slice().sort();
    let coveredLive = false;
    let coveredShadow = false;
    /** @type {string | null} */
    let blockedBy = null;
    for (const id of ids) {
      const row = detectors[id];
      if (!row || !row.active) {
        if (!blockedBy) blockedBy = blockReason(this, id, tiers);
        continue;
      }
      if (row.mode === 'shadow') coveredShadow = true;
      else coveredLive = true;
    }
    if (coveredLive || coveredShadow) blockedBy = null;
    if (coveredLive) live += 1;
    else if (coveredShadow) shadowOnly += 1;
    else blind += 1;
    techniques[technique] = { detectors: ids, coveredLive, coveredShadow, blockedBy };
  }
  return { tiers, detectors, techniques, summary: { live, shadowOnly, blind } };
}

/**
 * Canned attacks on a throwaway engine. The live engine is not changed.
 * @this {any}
 * @param {{ scenarios?: string[] }} [opts]
 */
function selftest(opts = {}) {
  const file = SCENARIOS;
  if (!file || !Array.isArray(file.scenarios)) {
    throw new HubvikError('SELFTEST_IS_INVALID', 'selftest is invalid');
  }
  if (file.scenarios.length > SCENARIO_CAP) {
    throw new HubvikError('SELFTEST_IS_INVALID', 'selftest is invalid');
  }
  /** @type {Set<string> | null} */
  let picked = null;
  if (opts.scenarios != null) {
    if (!Array.isArray(opts.scenarios)) {
      throw new HubvikError('SELFTEST_IS_INVALID', 'selftest is invalid');
    }
    picked = new Set(opts.scenarios);
  }
  const names = new Set(file.scenarios.map((/** @type {any} */ row) => row.name));
  if (picked) {
    for (const name of picked) {
      if (!names.has(name)) throw new HubvikError('SELFTEST_IS_INVALID', 'selftest is invalid');
    }
  }
  const { createEngine } = require('./engine');
  const box = /** @type {any} */ (createEngine(this.opts.raw));
  /** @type {{ scenario: string, expectedDetectors: string[], fired: string[], missing: string[], missingReason: string | null }[]} */
  const results = [];
  let n = 0;
  for (const row of file.scenarios) {
    if (picked && !picked.has(row.name)) continue;
    n += 1;
    const device = `__selftest-${n}`;
    const events = scenarioEvents(row.name, device, box.opts.learnMs);
    if (events.length > EVENT_CAP) {
      throw new HubvikError('SELFTEST_IS_INVALID', 'selftest is invalid');
    }
    /** @type {Set<string>} */
    const fired = new Set();
    const onAnomaly = (/** @type {any} */ item) => {
      if (item && item.device === device && typeof item.detector === 'string') {
        fired.add(item.detector);
      }
    };
    box.on('anomaly', onAnomaly);
    box.on('shadow-anomaly', onAnomaly);
    for (const event of events) box.feed(event);
    box.flush((events[events.length - 1] && events[events.length - 1].ts) || 0);
    box.removeListener('anomaly', onAnomaly);
    box.removeListener('shadow-anomaly', onAnomaly);
    const expected = Array.isArray(row.expectedDetectors) ? row.expectedDetectors.slice() : [];
    const missing = expected.filter((id) => !fired.has(id));
    results.push({
      scenario: row.name,
      expectedDetectors: expected,
      fired: [...fired].filter((id) => expected.includes(id)).sort(),
      missing,
      missingReason: missing.length ? missingReason(box, missing) : null,
    });
  }
  return results;
}

/**
 * @param {any} engine
 * @param {any} det
 * @returns {'live' | 'shadow'}
 */
function detectorMode(engine, det) {
  const over = engine.opts.detectors[det.id];
  if (det.meta && det.meta.mode === 'shadow' && !(over && over.mode === 'live')) return 'shadow';
  return 'live';
}

/**
 * @param {any} engine
 * @param {string} id
 * @param {Record<string, { enabled: boolean, eventsSeen: number }>} tiers
 * @returns {string}
 */
function blockReason(engine, id, tiers) {
  const det = engine.byId.get(id);
  const status = engine.detectorStatus[id];
  const missing = det
    ? det.requires.filter((/** @type {string} */ tier) => !tiers[tier].enabled)
    : [];
  if (missing.length) return `requires ${missing.join(',')}`;
  const unseen = det
    ? det.requires.filter(
        (/** @type {string} */ tier) => tiers[tier].enabled && tiers[tier].eventsSeen === 0,
      )
    : [];
  if (unseen.length) return `tier ${unseen[0]} never seen`;
  return (status && status.reason) || 'inactive';
}

/**
 * @param {any} engine
 * @param {string[]} missing
 * @returns {string}
 */
function missingReason(engine, missing) {
  for (const id of missing) {
    const status = engine.detectorStatus[id];
    if (status && status.reason) return status.reason;
  }
  return 'did not fire';
}

/**
 * @param {string} name
 * @param {string} device
 * @param {number} learnMs
 * @returns {any[]}
 */
function scenarioEvents(name, device, learnMs) {
  const at = learnMs > 0 ? learnMs : 1000;
  /** @type {any[]} */
  const events = [];
  if (learnMs > 0) {
    events.push({ device, dst: 'seed.example', bytes: 10, ts: 0 });
  }
  if (name === 'horizontal scan') {
    for (let i = 1; i <= 21; i += 1) {
      events.push(flow(device, at + i, `192.0.2.${i}`, 80));
    }
  } else if (name === 'egress flood') {
    events.push(flow(device, at, '8.8.8.8', 443, { pktsOut: 50_000, bytesOut: 1000, bytesIn: 0 }));
  } else if (name === 'DNS tunnel') {
    events.push({
      type: 'dns',
      device,
      ts: at,
      qname: '0123456789abcdefghijklmnopqrstuvwxyzabcde.example',
      qtype: 'TXT',
      rcode: 'NOERROR',
      resolver: '192.0.2.53',
    });
  } else if (name === 'new beacon') {
    for (let i = 0; i < 20; i += 1) {
      events.push(
        flow(device, at + i * 1000, '203.0.113.20', 443, { bytesOut: 100, bytesIn: 100 }),
      );
    }
  } else if (name === 'ARP gateway claim') {
    events.push(arp(device, at, '192.0.2.1', 'aa:bb:cc:dd:ee:01'));
    events.push(arp(device, at + 1, '192.0.2.1', 'aa:bb:cc:dd:ee:02'));
  } else if (name === 'OT dangerous op') {
    events.push({
      type: 'app',
      device,
      ts: at,
      proto: 'modbus',
      role: 'client',
      peerIp: '198.51.100.20',
      op: 'STOP',
    });
  } else if (name === 'proxy backconnect') {
    events.push(flow(device, at, '203.0.113.10', 443, { durationMs: 60_000 }));
    for (let i = 1; i <= 8; i += 1) {
      events.push(
        flow(device, at + 1000 + i, `203.0.113.${10 + i}`, 443, { durationMs: 100, bytesOut: 40 }),
      );
    }
  } else {
    throw new HubvikError('SELFTEST_IS_INVALID', 'selftest is invalid');
  }
  return events;
}

/**
 * @param {string} device
 * @param {number} ts
 * @param {string} dstIp
 * @param {number} dstPort
 * @param {Record<string, number>} [extra]
 */
function flow(device, ts, dstIp, dstPort, extra = {}) {
  return {
    type: 'flow',
    device,
    ts,
    srcIp: '192.0.2.10',
    srcPort: 40000,
    dstIp,
    dstPort,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 40,
    bytesIn: 0,
    pktsOut: 1,
    pktsIn: 0,
    durationMs: 10,
    ...extra,
  };
}

/**
 * @param {string} device
 * @param {number} ts
 * @param {string} ip
 * @param {string} mac
 */
function arp(device, ts, ip, mac) {
  return { type: 'arp', device, ts, op: 'reply', ip, mac };
}

module.exports = { coverage, selftest, SCENARIO_CAP, EVENT_CAP };
