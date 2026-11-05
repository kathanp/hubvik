// @ts-nocheck
'use strict';

const { HubvikError } = require('../errors');
const { adviceFor } = require('./advice');

const WAVE_DEVICES = 3;

function severityRank(severity) {
  if (severity === 'critical') return 4;
  if (severity === 'high') return 3;
  if (severity === 'medium') return 2;
  if (severity === 'low') return 1;
  if (severity === 'info') return 0;
  return 0;
}

function badTime(value) {
  return typeof value !== 'number' || !Number.isFinite(value);
}

function badQuiet(quietMs) {
  return (
    quietMs != null && (typeof quietMs !== 'number' || !Number.isFinite(quietMs) || quietMs < 0)
  );
}

function listCap(engine) {
  const cap = engine && engine.opts ? engine.opts.explainCap : null;
  return typeof cap === 'number' && cap >= 0 ? cap : 1000;
}

function clock(engine) {
  if (typeof engine.watermark === 'number') return engine.watermark;
  let max = 0;
  if (Array.isArray(engine.engines)) {
    for (const shard of engine.engines) {
      if (typeof shard.watermark === 'number' && shard.watermark > max) max = shard.watermark;
    }
  }
  return max;
}

function eachDevice(engine, visit) {
  if (engine.devices && typeof engine.devices.values === 'function') {
    for (const device of engine.devices.values()) visit(engine, device);
    return;
  }
  if (Array.isArray(engine.engines)) {
    for (const shard of engine.engines) eachDevice(shard, visit);
  }
}

function reportsOf(engine) {
  if (Array.isArray(engine._reports)) return engine._reports;
  /** @type {any[]} */
  const rows = [];
  if (Array.isArray(engine.engines)) {
    for (const shard of engine.engines) {
      if (Array.isArray(shard._reports)) rows.push(...shard._reports);
    }
  }
  return rows;
}

function suggestionOf(engine, device) {
  if (!engine.opts || engine.opts.classSuggest !== true || !device.classScores) return null;
  /** @type {{ class: string, score: number } | null} */
  let best = null;
  for (const classId of Object.keys(device.classScores)) {
    if (classId === '__proto__' || classId === 'constructor' || classId === 'prototype') continue;
    const score = device.classScores[classId];
    if (typeof score !== 'number') continue;
    if (!best || score > best.score || (score === best.score && classId < best.class)) {
      best = { class: classId, score };
    }
  }
  return best;
}

function readinessOf(engine, device) {
  if (typeof engine._quality !== 'function') return null;
  const row = engine._quality(device);
  return row && row.readiness ? row.readiness : null;
}

function blindOf(coverage) {
  const techniques = coverage && coverage.techniques ? coverage.techniques : {};
  /** @type {Array<{ technique: string, reason: string }>} */
  const rows = [];
  for (const name of Object.keys(techniques).sort()) {
    const row = techniques[name];
    if (!row || row.coveredLive || row.coveredShadow) continue;
    rows.push({ technique: name, reason: row.blockedBy || 'not covered' });
  }
  return rows;
}

function sentences(digestRows) {
  const map = new Map();
  for (const row of digestRows) {
    if (row && typeof row.device === 'string') map.set(row.device, String(row.text || ''));
  }
  return map;
}

function quietSet(engine, quietMs) {
  if (quietMs == null) return new Set();
  const rows = engine.quiet(clock(engine), quietMs).devices || [];
  return new Set(rows.map((/** @type {any} */ row) => row.device));
}

function meaning(id) {
  const advice = id ? adviceFor(id) : null;
  return advice ? advice.meaning : null;
}

function houseOf(engine, now, quietMs) {
  if (badTime(now)) throw new HubvikError('HOUSE_NOW_IS_INVALID', 'house now is invalid');
  if (badQuiet(quietMs)) throw new HubvikError('HOUSE_QUIET_IS_INVALID', 'quietMs is invalid');
  const overview = engine.overview(now);
  const digest = sentences(engine.digest(0).devices || []);
  const open = engine.openIncidents(now).incidents || [];
  const byDevice = new Map(open.map((/** @type {any} */ row) => [row.device, row]));
  const quiet = quietSet(engine, quietMs);
  /** @type {any[]} */
  const devices = [];
  eachDevice(engine, (owner, device) => {
    const id = device.id;
    const incident = byDevice.get(id) || null;
    const detector = incident && incident.detectors && incident.detectors[0];
    devices.push({
      device: id,
      mode: device.mode,
      class: device.deviceClass || null,
      suggestion: suggestionOf(owner, device),
      learning: device.mode === 'learning',
      lastSeen: device.lastTs,
      sentence: digest.get(id) || '',
      quiet: quiet.has(id),
      incident,
      advice: meaning(detector),
      readiness: readinessOf(owner, device),
    });
  });
  devices.sort((a, b) => (a.device < b.device ? -1 : a.device > b.device ? 1 : 0));
  return {
    now,
    overview,
    devices: devices.slice(0, listCap(engine)),
    blind: blindOf(engine.coverage(now)),
  };
}

function attentionOf(engine, now) {
  if (badTime(now)) throw new HubvikError('ATTENTION_NOW_IS_INVALID', 'attention now is invalid');
  const digest = sentences(engine.digest(0).devices || []);
  const rows = (engine.openIncidents(now).incidents || []).map((/** @type {any} */ incident) => {
    const detector = incident.detectors && incident.detectors[0];
    return {
      device: incident.device,
      severity: incident.severity,
      score: incident.score,
      sentence: digest.get(incident.device) || '',
      advice: meaning(detector),
    };
  });
  rows.sort((/** @type {any} */ a, /** @type {any} */ b) => {
    const rank = severityRank(b.severity) - severityRank(a.severity);
    if (rank !== 0) return rank;
    if (b.score !== a.score) return b.score - a.score;
    return a.device < b.device ? -1 : a.device > b.device ? 1 : 0;
  });
  return { now, items: rows.slice(0, listCap(engine)) };
}

function waveStarts(rows, sinceTs) {
  const sorted = rows
    .filter((row) => row && typeof row.ts === 'number' && typeof row.detector === 'string')
    .slice()
    .sort((a, b) => a.ts - b.ts);
  /** @type {Map<string, Set<string>>} */
  const seen = new Map();
  /** @type {Array<{ ts: number, kind: string, device: string, detector: string }>} */
  const out = [];
  for (const row of sorted) {
    let devices = seen.get(row.detector);
    if (!devices) {
      devices = new Set();
      seen.set(row.detector, devices);
    }
    const before = devices.size;
    devices.add(String(row.device));
    if (before < WAVE_DEVICES && devices.size === WAVE_DEVICES && row.ts >= sinceTs) {
      out.push({
        ts: row.ts,
        kind: 'wave-started',
        device: String(row.device),
        detector: row.detector,
      });
    }
  }
  return out;
}

function timelineOf(engine, sinceTs, quietMs) {
  if (badTime(sinceTs)) {
    throw new HubvikError('TIMELINE_SINCE_IS_INVALID', 'timeline sinceTs is invalid');
  }
  if (badQuiet(quietMs)) throw new HubvikError('TIMELINE_QUIET_IS_INVALID', 'quietMs is invalid');
  const quiet = quietSet(engine, quietMs);
  /** @type {any[]} */
  const rows = [];
  eachDevice(engine, (_owner, device) => {
    if (typeof device.learnStart === 'number' && device.learnStart >= sinceTs) {
      rows.push({ ts: device.learnStart, kind: 'device-seen', device: device.id });
    }
    if (quiet.has(device.id) && typeof device.lastTs === 'number' && device.lastTs >= sinceTs) {
      rows.push({ ts: device.lastTs, kind: 'device-quiet', device: device.id });
    }
    const incident = device.incident;
    if (incident && typeof incident.firstTs === 'number' && incident.firstTs >= sinceTs) {
      rows.push({ ts: incident.firstTs, kind: 'incident-opened', device: device.id });
    }
  });
  rows.push(...waveStarts(reportsOf(engine), sinceTs));
  rows.sort((a, b) => a.ts - b.ts || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0));
  return { sinceTs, events: rows.slice(0, listCap(engine)) };
}

function incidentWindow(engine) {
  const value = engine.opts && engine.opts.incidentWindowMs;
  return typeof value === 'number' && value >= 0 ? value : 30 * 60 * 1000;
}

function changesOf(engine, sinceTs, quietMs) {
  if (badTime(sinceTs)) {
    throw new HubvikError('CHANGES_SINCE_IS_INVALID', 'changes sinceTs is invalid');
  }
  if (badQuiet(quietMs)) throw new HubvikError('CHANGES_QUIET_IS_INVALID', 'quietMs is invalid');
  const now = clock(engine);
  const windowMs = incidentWindow(engine);
  const quiet = quietSet(engine, quietMs);
  /** @type {string[]} */
  const devicesFirstSeen = [];
  /** @type {string[]} */
  const devicesQuiet = [];
  /** @type {string[]} */
  const incidentsOpened = [];
  /** @type {string[]} */
  const incidentsClosed = [];
  eachDevice(engine, (_owner, device) => {
    if (typeof device.learnStart === 'number' && device.learnStart >= sinceTs) {
      devicesFirstSeen.push(device.id);
    }
    if (quiet.has(device.id) && typeof device.lastTs === 'number') {
      const quietAt = device.lastTs + (quietMs || 0);
      if (quietAt >= sinceTs && quietAt <= now) devicesQuiet.push(device.id);
    }
    const incident = device.incident;
    if (!incident) return;
    if (typeof incident.firstTs === 'number' && incident.firstTs >= sinceTs) {
      incidentsOpened.push(device.id);
    }
    if (typeof incident.lastTs !== 'number') return;
    const closedAt = incident.lastTs + windowMs;
    const stillOpen = now - incident.lastTs <= windowMs;
    if (!stillOpen && closedAt >= sinceTs && closedAt <= now) incidentsClosed.push(device.id);
  });
  const cap = listCap(engine);
  const sort = (/** @type {string[]} */ rows) => rows.sort().slice(0, cap);
  return {
    sinceTs,
    devicesFirstSeen: sort(devicesFirstSeen),
    devicesQuiet: sort(devicesQuiet),
    incidentsOpened: sort(incidentsOpened),
    incidentsClosed: sort(incidentsClosed),
  };
}

module.exports = { houseOf, attentionOf, timelineOf, changesOf };
