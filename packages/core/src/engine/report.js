'use strict';

const { HubvikError } = require('../errors');
const { precisionOf } = require('./feedback');
const STAGES = require('../data/stages.json');
const ATTACK = require('../data/attack-map.json');

const CLIP = 200;
const ACTIONS = new Set(['review', 'relearn', 'isolate-device', 'block-destination', 'rate-limit']);

/**
 * Remember one live anomaly for digest() and exportDecisions().
 * The ring is capped by explainCap. It is not part of the baseline or the checkpoint.
 * @param {any} engine
 * @param {any} anomaly
 * @returns {void}
 */
function noteReport(engine, anomaly) {
  pushRing(engine, '_reports', anomaly);
}

/**
 * Remember one shadow anomaly. Same cap and same row as the live ring.
 * The ring is not part of the baseline or the checkpoint. This does not emit.
 * @param {any} engine
 * @param {any} anomaly
 * @returns {void}
 */
function noteShadow(engine, anomaly) {
  pushRing(engine, '_shadowReports', anomaly);
}

/**
 * @param {any} engine
 * @param {string} key
 * @param {any} anomaly
 * @returns {void}
 */
function pushRing(engine, key, anomaly) {
  if (!Array.isArray(engine[key])) engine[key] = [];
  const data = anomaly.data && typeof anomaly.data === 'object' ? anomaly.data : {};
  engine[key].push({
    device: String(anomaly.device),
    detector: String(anomaly.detector),
    ts: typeof anomaly.ts === 'number' ? anomaly.ts : 0,
    confidence: typeof anomaly.confidence === 'number' ? anomaly.confidence : null,
    actual: clip(anomaly.actual),
    expected: clip(anomaly.expected),
    destination: destinationOf(data),
    fingerprint: typeof anomaly.fingerprint === 'string' ? anomaly.fingerprint : '',
    response: clipHints(anomaly.response),
  });
  const cap = engine.opts && engine.opts.explainCap ? engine.opts.explainCap : 1000;
  while (engine[key].length > cap) engine[key].shift();
}

/**
 * One plain-language summary per device for anomalies at or after sinceTs.
 * @param {any[]} rows
 * @param {number} sinceTs
 * @returns {{ sinceTs: number, devices: { device: string, count: number, text: string }[] }}
 */
function digestOf(rows, sinceTs) {
  if (typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)) {
    throw new HubvikError('DIGEST_SINCE_IS_INVALID', 'digest sinceTs is invalid');
  }
  /** @type {Map<string, { device: string, count: number, lines: string[] }>} */
  const byDevice = new Map();
  const list = Array.isArray(rows) ? rows : [];
  const ordered = list
    .filter((row) => row && typeof row.ts === 'number' && row.ts >= sinceTs)
    .slice()
    .sort(
      (a, b) =>
        a.ts - b.ts ||
        String(a.device).localeCompare(String(b.device)) ||
        String(a.detector).localeCompare(String(b.detector)),
    );
  for (const row of ordered) {
    let bucket = byDevice.get(row.device);
    if (!bucket) {
      bucket = { device: row.device, count: 0, lines: [] };
      byDevice.set(row.device, bucket);
    }
    bucket.count += 1;
    if (bucket.lines.length < 20) bucket.lines.push(sentence(row));
  }
  const devices = [...byDevice.values()]
    .sort((a, b) => (a.device < b.device ? -1 : 1))
    .map((bucket) => ({
      device: bucket.device,
      count: bucket.count,
      text: bucket.lines.join(' '),
    }));
  return { sinceTs, devices };
}

/**
 * Flagged destinations the host may upload. This function opens no socket.
 * @param {any[]} rows
 * @returns {{ device: string, detector: string, ts: number, confidence: number | null, destination: string | null, fingerprint: string }[]}
 */
function decisionsOf(rows) {
  const list = Array.isArray(rows) ? rows : [];
  return list
    .filter((row) => row && typeof row.detector === 'string')
    .map((row) => ({
      device: String(row.device),
      detector: String(row.detector),
      ts: typeof row.ts === 'number' ? row.ts : 0,
      confidence: typeof row.confidence === 'number' ? row.confidence : null,
      destination: typeof row.destination === 'string' ? row.destination : null,
      fingerprint: typeof row.fingerprint === 'string' ? row.fingerprint : '',
    }))
    .sort(
      (a, b) =>
        a.ts - b.ts ||
        a.device.localeCompare(b.device) ||
        a.detector.localeCompare(b.detector) ||
        a.fingerprint.localeCompare(b.fingerprint),
    );
}

/**
 * Devices already seen. Ports and app names come from detector state that already exists.
 * Class suggestions are included only when classSuggest is on. The engine does not assign a class.
 * @param {any} engine
 * @returns {any[]}
 */
function inventoryOf(engine) {
  /** @type {any[]} */
  const rows = [];
  for (const device of engine.devices.values()) {
    if (!device || !device.seen) continue;
    /** @type {Record<string, unknown>} */
    const row = {
      device: String(device.id),
      lastSeen: typeof device.lastTs === 'number' ? device.lastTs : null,
      class: typeof device.deviceClass === 'string' ? device.deviceClass : null,
      addresses: addressesOf(engine, String(device.id)),
      ports: portsOf(device),
      protocols: protocolsOf(device),
      apps: appsOf(device),
    };
    if (engine.opts && engine.opts.classSuggest) row.suggestions = suggestionsOf(device);
    rows.push(row);
  }
  rows.sort((a, b) => String(a.device).localeCompare(String(b.device)));
  return rows;
}

/**
 * Merge shard inventories. The same device id keeps the later lastSeen and the union of lists.
 * @param {any[]} rows
 * @returns {any[]}
 */
function mergeInventory(rows) {
  /** @type {Map<string, any>} */
  const byId = new Map();
  for (const row of rows) {
    const id = String(row.device);
    const prev = byId.get(id);
    if (!prev) {
      byId.set(id, {
        ...row,
        addresses: [...(row.addresses || [])],
        ports: [...(row.ports || [])],
        protocols: [...(row.protocols || [])],
        apps: [...(row.apps || [])],
      });
      continue;
    }
    if (
      typeof row.lastSeen === 'number' &&
      (prev.lastSeen == null || row.lastSeen > prev.lastSeen)
    ) {
      prev.lastSeen = row.lastSeen;
    }
    if (row.class) prev.class = row.class;
    prev.addresses = union(prev.addresses, row.addresses, (a, b) => (a < b ? -1 : 1));
    prev.ports = union(prev.ports, row.ports, (a, b) => a - b);
    prev.protocols = union(prev.protocols, row.protocols, (a, b) => (a < b ? -1 : 1));
    prev.apps = union(prev.apps, row.apps, (a, b) => (a < b ? -1 : 1));
    if (row.suggestions) prev.suggestions = row.suggestions;
  }
  return [...byId.values()].sort((a, b) => (a.device < b.device ? -1 : 1));
}

const reportMethods = {
  /**
   * @this {any}
   * @param {number} sinceTs
   */
  digest(sinceTs) {
    return digestOf(this._reports, sinceTs);
  },

  /**
   * @this {any}
   */
  inventory() {
    return inventoryOf(this);
  },

  /**
   * JSON document of flagged destinations. The host may POST it. Nothing is sent from here.
   * @this {any}
   * @returns {string}
   */
  exportDecisions() {
    return JSON.stringify({ decisions: decisionsOf(this._reports) });
  },

  /**
   * How often each detector fired at or after sinceTs. Reads the report ring only.
   * @this {any}
   * @param {number} sinceTs
   */
  counts(sinceTs) {
    return countsOf(this._reports, sinceTs);
  },

  /**
   * Text hints already attached to live anomalies. Empty unless responseHints is on.
   * This does not apply a hint.
   * @this {any}
   * @param {number} sinceTs
   */
  hints(sinceTs) {
    return hintsOf(this._reports, sinceTs);
  },

  /**
   * Detectors whose labeled false-positive rate is already over the noisy bar.
   * Does not change a threshold.
   * @this {any}
   */
  noisy() {
    return noisyFrom(this._feedback);
  },

  /**
   * Devices already seen whose last event is at least quietMs before now.
   * Does not emit went-silent and does not change that detector.
   * @this {any}
   * @param {number} now
   * @param {number} quietMs
   */
  quiet(now, quietMs) {
    return quietOf(this, now, quietMs);
  },

  /**
   * Stages and techniques already tagged on live anomalies. Does not run a detector.
   * @this {any}
   * @param {number} sinceTs
   */
  attacks(sinceTs) {
    return attacksOf(this._reports, sinceTs);
  },

  /**
   * One detector firing on three or more devices. The same device count campaigns use.
   * @this {any}
   * @param {number} sinceTs
   */
  waves(sinceTs) {
    return wavesOf(this._reports, sinceTs);
  },

  /**
   * Incidents the engine already opened and has not closed. Does not emit.
   * @this {any}
   * @param {number} now
   */
  openIncidents(now) {
    return openIncidentsOf(this, now);
  },

  /**
   * Shadow anomalies already emitted. Same shape as attacks(). Does not emit.
   * @this {any}
   * @param {number} sinceTs
   */
  shadow(sinceTs) {
    return shadowOf(this._shadowReports, sinceTs);
  },

  /**
   * Campaigns the engine already opened and has not closed. Does not emit.
   * @this {any}
   * @param {number} now
   */
  campaigns(now) {
    return campaignsOf(this, now);
  },

  /**
   * Attacks, waves, incidents, campaigns, shadow hits, and counts in one read.
   * Does not emit and does not run a detector.
   * @this {any}
   * @param {number} now
   * @param {number} [sinceTs]
   */
  overview(now, sinceTs) {
    return overviewOf(this, now, sinceTs);
  },
};

/**
 * @param {any} row
 * @returns {string}
 */
function sentence(row) {
  const actual = row.actual ? String(row.actual) : row.detector;
  let text = `${row.detector}: ${actual}.`;
  if (row.expected) text += ` Expected ${row.expected}.`;
  if (row.destination && !actual.includes(row.destination)) {
    text += ` Destination ${row.destination}.`;
  }
  return text;
}

/**
 * @param {any} data
 * @returns {string | null}
 */
function destinationOf(data) {
  for (const key of ['dstName', 'qname', 'dst', 'dstIp', 'domain', 'peerIp', 'name']) {
    const value = data[key];
    if (typeof value === 'string' && value.length > 0 && value.length <= 255) return value;
  }
  return null;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function clip(value) {
  const text = value == null ? '' : String(value);
  return text.length > CLIP ? text.slice(0, CLIP) : text;
}

/**
 * @param {any} engine
 * @param {string} deviceId
 * @returns {string[]}
 */
function addressesOf(engine, deviceId) {
  const map = engine.scratch && engine.scratch.get ? engine.scratch.get('identity') : null;
  if (!(map instanceof Map)) return [];
  /** @type {string[]} */
  const out = [];
  for (const [ip, row] of map) {
    if (row && row.mac === deviceId && out.length < 16) out.push(String(ip));
  }
  return out.sort();
}

/**
 * @param {any} device
 * @returns {number[]}
 */
function portsOf(device) {
  const state = stateOf(device, 'new-port');
  if (!state || !state.ports || typeof state.ports.toArray !== 'function') return [];
  /** @type {Set<number>} */
  const nums = new Set();
  for (const key of state.ports.toArray()) {
    const part = String(key).split(':').pop();
    const n = Number(part);
    if (Number.isInteger(n) && n >= 0 && n <= 65535) nums.add(n);
  }
  return [...nums].sort((a, b) => a - b).slice(0, 32);
}

/**
 * @param {any} device
 * @returns {string[]}
 */
function protocolsOf(device) {
  const state = stateOf(device, 'new-protocol');
  if (!state || !state.protos || typeof state.protos.toArray !== 'function') return [];
  return state.protos
    .toArray()
    .map((/** @type {unknown} */ value) => String(value))
    .sort()
    .slice(0, 16);
}

/**
 * @param {any} device
 * @returns {string[]}
 */
function appsOf(device) {
  /** @type {string[]} */
  const out = [];
  const mqtt = stateOf(device, 'mqtt-new-broker');
  if (mqtt && mqtt.brokers && mqtt.brokers.size > 0) out.push('mqtt');
  const ot = stateOf(device, 'ot-new-master');
  if (ot && ot.seen && ot.seen.size > 0) out.push('ot');
  const stream = stateOf(device, 'stream-to-new-destination');
  if (stream && stream.seen && stream.seen.size > 0) out.push('rtsp');
  const onvif = stateOf(device, 'onvif-config-change');
  if (onvif && onvif.fired && onvif.fired.size > 0) out.push('onvif');
  return out;
}

/**
 * @param {any} device
 * @param {string} id
 * @returns {any}
 */
function stateOf(device, id) {
  if (!device.states || typeof device.states.get !== 'function') return null;
  return device.states.get(id) || null;
}

/**
 * @param {any} device
 * @returns {{ class: string, score: number, reasons: string[] }[]}
 */
function suggestionsOf(device) {
  if (!device.classScores) return [];
  return Object.keys(device.classScores)
    .map((classId) => ({
      class: classId,
      score: device.classScores[classId],
      reasons: (device.classReasons && device.classReasons[classId]) || [],
    }))
    .sort((a, b) => b.score - a.score || (a.class < b.class ? -1 : 1));
}

/**
 * @param {any[]} left
 * @param {any[]} right
 * @param {(a: any, b: any) => number} compare
 * @returns {any[]}
 */
/**
 * @param {unknown} raw
 * @returns {{ action: string, target: string, reversible: true, minConfidence: number }[]}
 */
function clipHints(raw) {
  if (!Array.isArray(raw)) return [];
  /** @type {{ action: string, target: string, reversible: true, minConfidence: number }[]} */
  const out = [];
  for (const hint of raw) {
    if (!hint || typeof hint !== 'object' || Array.isArray(hint)) continue;
    const action = /** @type {any} */ (hint).action;
    if (!ACTIONS.has(action)) continue;
    const target = /** @type {any} */ (hint).target;
    const min = /** @type {any} */ (hint).minConfidence;
    out.push({
      action,
      target: typeof target === 'string' ? target.slice(0, 64) : '',
      reversible: true,
      minConfidence: typeof min === 'number' && Number.isFinite(min) ? min : 0,
    });
    if (out.length >= 4) break;
  }
  return out;
}

/**
 * Fire counts from the report ring.
 * @param {any[]} rows
 * @param {number} sinceTs
 */
function countsOf(rows, sinceTs) {
  if (typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)) {
    throw new HubvikError('COUNTS_SINCE_IS_INVALID', 'counts sinceTs is invalid');
  }
  /** @type {Map<string, { detector: string, count: number, devices: Set<string> }>} */
  const byDetector = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (
      !row ||
      typeof row.ts !== 'number' ||
      row.ts < sinceTs ||
      typeof row.detector !== 'string'
    ) {
      continue;
    }
    let bucket = byDetector.get(row.detector);
    if (!bucket) {
      bucket = { detector: row.detector, count: 0, devices: new Set() };
      byDetector.set(row.detector, bucket);
    }
    bucket.count += 1;
    bucket.devices.add(String(row.device));
  }
  const detectors = [...byDetector.values()]
    .map((bucket) => ({
      detector: bucket.detector,
      count: bucket.count,
      devices: bucket.devices.size,
    }))
    .sort((a, b) => b.count - a.count || (a.detector < b.detector ? -1 : 1));
  return { sinceTs, detectors };
}

/**
 * Hint text already stored on live anomalies. Nothing is applied.
 * @param {any[]} rows
 * @param {number} sinceTs
 */
function hintsOf(rows, sinceTs) {
  if (typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)) {
    throw new HubvikError('HINTS_SINCE_IS_INVALID', 'hints sinceTs is invalid');
  }
  /** @type {{ device: string, detector: string, ts: number, action: string, target: string, reversible: true, minConfidence: number }[]} */
  const hints = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || typeof row.ts !== 'number' || row.ts < sinceTs || !Array.isArray(row.response)) {
      continue;
    }
    for (const hint of row.response) {
      hints.push({
        device: String(row.device),
        detector: String(row.detector),
        ts: row.ts,
        action: hint.action,
        target: hint.target,
        reversible: true,
        minConfidence: hint.minConfidence,
      });
    }
  }
  hints.sort(
    (a, b) => a.ts - b.ts || (a.device < b.device ? -1 : 1) || (a.detector < b.detector ? -1 : 1),
  );
  return { sinceTs, hints };
}

/**
 * @param {number} now
 * @param {number} quietMs
 */
function requireQuiet(now, quietMs) {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new HubvikError('QUIET_NOW_IS_INVALID', 'quiet now is invalid');
  }
  if (typeof quietMs !== 'number' || !Number.isFinite(quietMs) || quietMs < 0) {
    throw new HubvikError('QUIET_MS_IS_INVALID', 'quiet ms is invalid');
  }
}

/**
 * Seen devices with no event for quietMs. Does not run went-silent.
 * @param {any} engine
 * @param {number} now
 * @param {number} quietMs
 */
function quietOf(engine, now, quietMs) {
  requireQuiet(now, quietMs);
  return { now, quietMs, devices: quietRows(engine, now, quietMs) };
}

/**
 * @param {any} engine
 * @param {number} now
 * @param {number} quietMs
 */
function quietRows(engine, now, quietMs) {
  /** @type {{ device: string, lastSeen: number }[]} */
  const devices = [];
  if (!engine || !engine.devices || typeof engine.devices.values !== 'function') return devices;
  for (const device of engine.devices.values()) {
    if (!device || !device.seen) continue;
    if (typeof device.lastTs !== 'number' || !Number.isFinite(device.lastTs)) continue;
    if (now - device.lastTs < quietMs) continue;
    devices.push({ device: String(device.id), lastSeen: device.lastTs });
  }
  devices.sort((a, b) => a.lastSeen - b.lastSeen || (a.device < b.device ? -1 : 1));
  return devices;
}

/**
 * Keep the later lastSeen, then drop devices that are no longer quiet.
 * @param {{ device: string, lastSeen: number }[]} rows
 * @param {number} now
 * @param {number} quietMs
 */
function mergeQuiet(rows, now, quietMs) {
  requireQuiet(now, quietMs);
  /** @type {Map<string, { device: string, lastSeen: number }>} */
  const byDevice = new Map();
  for (const row of rows) {
    if (!row || typeof row.device !== 'string') continue;
    const prev = byDevice.get(row.device);
    if (!prev || row.lastSeen > prev.lastSeen) byDevice.set(row.device, row);
  }
  const devices = [...byDevice.values()]
    .filter((row) => now - row.lastSeen >= quietMs)
    .sort((a, b) => a.lastSeen - b.lastSeen || (a.device < b.device ? -1 : 1));
  return { now, quietMs, devices };
}

/**
 * Same labels as stats().precision. A row is included when fpRate is over one half and n is at least 10.
 * @param {any[]} rows
 */
function noisyFrom(rows) {
  const precision = precisionOf({ _feedback: Array.isArray(rows) ? rows : [] });
  /** @type {{ detector: string, fpRate: number, n: number }[]} */
  const out = [];
  for (const [detector, row] of Object.entries(precision)) {
    const n = row.tp + row.fp + row.benign + row.unknown;
    if (row.fpRate > 0.5 && n >= 10) out.push({ detector, fpRate: row.fpRate, n });
  }
  out.sort((a, b) => b.fpRate - a.fpRate || (a.detector < b.detector ? -1 : 1));
  return out;
}

/**
 * @param {any[]} left
 * @param {any[]} right
 * @param {(a: any, b: any) => number} compare
 * @returns {any[]}
 */
function union(left, right, compare) {
  const set = new Set([...(left || []), ...(right || [])]);
  return [...set].sort(compare);
}

/**
 * Kill-chain stages and technique ids already attached to live anomalies.
 * A device is progressing when two or more stages have been seen.
 * @param {any[]} rows
 * @param {number} sinceTs
 */
function attacksOf(rows, sinceTs) {
  if (typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)) {
    throw new HubvikError('ATTACKS_SINCE_IS_INVALID', 'attacks sinceTs is invalid');
  }
  /** @type {Map<string, any>} */
  const byDevice = new Map();
  const ordered = (Array.isArray(rows) ? rows : [])
    .filter((row) => row && typeof row.ts === 'number' && row.ts >= sinceTs)
    .slice()
    .sort(
      (a, b) =>
        a.ts - b.ts ||
        String(a.device).localeCompare(String(b.device)) ||
        String(a.detector).localeCompare(String(b.detector)),
    );
  for (const row of ordered) {
    let bucket = byDevice.get(row.device);
    if (!bucket) {
      bucket = {
        device: String(row.device),
        count: 0,
        firstTs: row.ts,
        lastTs: row.ts,
        detectors: [],
        stages: [],
        techniques: [],
        destinations: [],
        seenDet: new Set(),
        seenStage: new Set(),
        seenTech: new Set(),
        seenDest: new Set(),
      };
      byDevice.set(row.device, bucket);
    }
    bucket.count += 1;
    bucket.lastTs = row.ts;
    if (bucket.detectors.length < 16 && !bucket.seenDet.has(row.detector)) {
      bucket.seenDet.add(row.detector);
      bucket.detectors.push(String(row.detector));
    }
    const stage = /** @type {Record<string, string>} */ (STAGES)[row.detector];
    if (stage && !bucket.seenStage.has(stage)) {
      bucket.seenStage.add(stage);
      bucket.stages.push(stage);
    }
    const techs = /** @type {Record<string, string[]>} */ (ATTACK)[row.detector];
    if (Array.isArray(techs)) {
      for (const tech of techs) {
        if (bucket.techniques.length >= 8) break;
        if (!bucket.seenTech.has(tech)) {
          bucket.seenTech.add(tech);
          bucket.techniques.push(tech);
        }
      }
    }
    if (
      typeof row.destination === 'string' &&
      row.destination &&
      bucket.destinations.length < 8 &&
      !bucket.seenDest.has(row.destination)
    ) {
      bucket.seenDest.add(row.destination);
      bucket.destinations.push(row.destination);
    }
  }
  const devices = [...byDevice.values()]
    .map((bucket) => ({
      device: bucket.device,
      count: bucket.count,
      firstTs: bucket.firstTs,
      lastTs: bucket.lastTs,
      detectors: bucket.detectors,
      stages: bucket.stages,
      techniques: bucket.techniques,
      destinations: bucket.destinations,
      progressing: bucket.stages.length >= 2,
    }))
    .sort(
      (a, b) =>
        Number(b.progressing) - Number(a.progressing) ||
        b.count - a.count ||
        (a.device < b.device ? -1 : 1),
    );
  return { sinceTs, devices };
}

/**
 * A detector that already fired on three or more devices. Does not change a threshold.
 * @param {any[]} rows
 * @param {number} sinceTs
 */
function wavesOf(rows, sinceTs) {
  if (typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)) {
    throw new HubvikError('WAVES_SINCE_IS_INVALID', 'waves sinceTs is invalid');
  }
  /** @type {Map<string, { detector: string, count: number, devices: Set<string>, stage: string | null }>} */
  const byDetector = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    if (
      !row ||
      typeof row.ts !== 'number' ||
      row.ts < sinceTs ||
      typeof row.detector !== 'string'
    ) {
      continue;
    }
    let bucket = byDetector.get(row.detector);
    if (!bucket) {
      const stage = /** @type {Record<string, string>} */ (STAGES)[row.detector] || null;
      bucket = { detector: row.detector, count: 0, devices: new Set(), stage };
      byDetector.set(row.detector, bucket);
    }
    bucket.count += 1;
    bucket.devices.add(String(row.device));
  }
  const waves = [...byDetector.values()]
    .filter((bucket) => bucket.devices.size >= 3)
    .map((bucket) => ({
      detector: bucket.detector,
      stage: bucket.stage,
      devices: bucket.devices.size,
      count: bucket.count,
    }))
    .sort(
      (a, b) => b.devices - a.devices || b.count - a.count || (a.detector < b.detector ? -1 : 1),
    );
  return { sinceTs, waves };
}

/**
 * @param {any} engine
 * @param {number} now
 */
function openIncidentsOf(engine, now) {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new HubvikError('OPEN_INCIDENTS_NOW_IS_INVALID', 'open incidents now is invalid');
  }
  const windowMs =
    engine && engine.opts && typeof engine.opts.incidentWindowMs === 'number'
      ? engine.opts.incidentWindowMs
      : 30 * 60 * 1000;
  /** @type {any[]} */
  const incidents = [];
  if (!engine || !engine.devices || typeof engine.devices.values !== 'function') {
    return { now, incidents };
  }
  for (const device of engine.devices.values()) {
    const incident = device && device.incident;
    if (!incident || typeof incident.lastTs !== 'number') continue;
    if (now < incident.firstTs || now - incident.lastTs > windowMs) continue;
    /** @type {string[]} */
    const detectors = [];
    const seen = new Set();
    for (const id of incident.detectors || []) {
      if (seen.has(id)) continue;
      seen.add(id);
      detectors.push(String(id));
      if (detectors.length >= 16) break;
    }
    incidents.push({
      id: incident.id,
      device: String(incident.device),
      stages: [...incident.stages],
      score: incident.score,
      severity: incident.severity,
      detectors,
      firstTs: incident.firstTs,
      lastTs: incident.lastTs,
    });
  }
  incidents.sort((a, b) => b.score - a.score || (a.device < b.device ? -1 : 1));
  return { now, incidents };
}

/**
 * Shadow anomalies grouped the same way as attacks(). Does not emit.
 * @param {any[]} rows
 * @param {number} sinceTs
 */
function shadowOf(rows, sinceTs) {
  if (typeof sinceTs !== 'number' || !Number.isFinite(sinceTs)) {
    throw new HubvikError('SHADOW_SINCE_IS_INVALID', 'shadow sinceTs is invalid');
  }
  return attacksOf(rows, sinceTs);
}

/**
 * Campaigns already stored whose lastTs is still inside the incident window.
 * Does not emit and does not change a score.
 * @param {any} engine
 * @param {number} now
 */
function campaignsOf(engine, now) {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new HubvikError('CAMPAIGNS_NOW_IS_INVALID', 'campaigns now is invalid');
  }
  const windowMs = windowOf(engine);
  /** @type {any[]} */
  const campaigns = [];
  const list = engine && Array.isArray(engine._campaigns) ? engine._campaigns : [];
  for (const campaign of list) {
    const row = campaignRow(campaign, now, windowMs);
    if (row) campaigns.push(row);
  }
  campaigns.sort((a, b) => b.score - a.score || (a.id < b.id ? -1 : 1));
  return { now, campaigns };
}

/**
 * Same device set on two shards keeps the later lastTs.
 * @param {any[]} rows
 * @param {number} now
 */
function mergeCampaigns(rows, now) {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new HubvikError('CAMPAIGNS_NOW_IS_INVALID', 'campaigns now is invalid');
  }
  /** @type {Map<string, any>} */
  const byDevices = new Map();
  for (const row of rows) {
    if (!row || !Array.isArray(row.devices)) continue;
    const key = row.devices
      .map((/** @type {string} */ id) => String(id))
      .sort()
      .join('\n');
    const prev = byDevices.get(key);
    if (!prev || row.lastTs > prev.lastTs) byDevices.set(key, row);
  }
  const campaigns = [...byDevices.values()].sort(
    (a, b) => b.score - a.score || (a.id < b.id ? -1 : 1),
  );
  return { now, campaigns };
}

/**
 * @param {any} engine
 * @returns {number}
 */
function windowOf(engine) {
  return engine && engine.opts && typeof engine.opts.incidentWindowMs === 'number'
    ? engine.opts.incidentWindowMs
    : 30 * 60 * 1000;
}

/**
 * @param {any} campaign
 * @param {number} now
 * @param {number} windowMs
 * @returns {any}
 */
function campaignRow(campaign, now, windowMs) {
  if (!campaign || typeof campaign.lastTs !== 'number' || typeof campaign.firstTs !== 'number') {
    return null;
  }
  if (now < campaign.firstTs || now - campaign.lastTs > windowMs) return null;
  const stages = Array.isArray(campaign.stages)
    ? campaign.stages.map((/** @type {string} */ stage) => String(stage))
    : [...(campaign.stages || [])].map((stage) => String(stage));
  /** @type {any[]} */
  const edges = [];
  for (const edge of campaign.edges || []) {
    if (!edge || edges.length >= 64) break;
    edges.push({
      from: String(edge.from),
      to: String(edge.to),
      via: String(edge.via),
      ts: typeof edge.ts === 'number' ? edge.ts : 0,
    });
  }
  return {
    id: String(campaign.id),
    devices: (campaign.devices || []).slice(0, 64).map((/** @type {string} */ id) => String(id)),
    edges,
    stages,
    score: campaign.score,
    severity: campaign.severity,
    firstTs: campaign.firstTs,
    lastTs: campaign.lastTs,
  };
}

/**
 * One object for the reads a host otherwise calls separately. Does not emit.
 * `sinceTs` left out means 0.
 * @param {any} engine
 * @param {number} now
 * @param {number} [sinceTs]
 */
function overviewOf(engine, now, sinceTs) {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new HubvikError('OVERVIEW_NOW_IS_INVALID', 'overview now is invalid');
  }
  const since = sinceTs == null ? 0 : sinceTs;
  if (typeof since !== 'number' || !Number.isFinite(since)) {
    throw new HubvikError('OVERVIEW_SINCE_IS_INVALID', 'overview sinceTs is invalid');
  }
  return {
    now,
    sinceTs: since,
    attacks: engine.attacks(since).devices,
    waves: engine.waves(since).waves,
    incidents: engine.openIncidents(now).incidents,
    campaigns: engine.campaigns(now).campaigns,
    shadow: engine.shadow(since).devices,
    counts: engine.counts(since).detectors,
  };
}

/**
 * @param {any[]} rows
 * @param {number} now
 */
function mergeOpen(rows, now) {
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new HubvikError('OPEN_INCIDENTS_NOW_IS_INVALID', 'open incidents now is invalid');
  }
  /** @type {Map<string, any>} */
  const byDevice = new Map();
  for (const row of rows) {
    if (!row || typeof row.device !== 'string') continue;
    const prev = byDevice.get(row.device);
    if (!prev || row.lastTs > prev.lastTs) byDevice.set(row.device, row);
  }
  const incidents = [...byDevice.values()].sort(
    (a, b) => b.score - a.score || (a.device < b.device ? -1 : 1),
  );
  return { now, incidents };
}

module.exports = {
  noteReport,
  noteShadow,
  digestOf,
  decisionsOf,
  inventoryOf,
  mergeInventory,
  countsOf,
  hintsOf,
  quietOf,
  mergeQuiet,
  noisyFrom,
  attacksOf,
  wavesOf,
  openIncidentsOf,
  mergeOpen,
  shadowOf,
  campaignsOf,
  mergeCampaigns,
  overviewOf,
  reportMethods,
};
