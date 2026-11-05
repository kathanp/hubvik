// @ts-nocheck
'use strict';

const { HubvikError } = require('../errors');
const { FORBIDDEN_KEYS } = require('./constants');
const { runScenarios } = require('./coverage');

const WINDOW_MS = 30 * 60 * 1000;

function badTime(value) {
  return typeof value !== 'number' || !Number.isFinite(value);
}

function listCap(engine) {
  const cap = engine && engine.opts ? engine.opts.explainCap : null;
  return typeof cap === 'number' && cap >= 0 ? cap : 1000;
}

function rawOpts(engine) {
  if (engine.opts && engine.opts.raw) return engine.opts.raw;
  const shard = engine.engines && engine.engines[0];
  return shard && shard.opts ? shard.opts.raw : {};
}

function eachEngine(engine, visit) {
  if (engine.devices && typeof engine.devices.get === 'function') visit(engine);
  if (Array.isArray(engine.engines)) {
    for (const shard of engine.engines) visit(shard);
  }
}

function findDevice(engine, id) {
  let found = null;
  eachEngine(engine, (owner) => {
    if (found || !owner.devices) return;
    const device = owner.devices.get(id);
    if (device) found = { owner, device };
  });
  return found;
}

function badDevice(id) {
  return typeof id !== 'string' || id.length === 0 || id.length > 255 || FORBIDDEN_KEYS.has(id);
}

function stringsOf(state, key) {
  if (!state || !state[key]) return [];
  const value = state[key];
  const list = typeof value.toArray === 'function' ? value.toArray() : value;
  if (!Array.isArray(list)) return [];
  return list.map((item) => String(item)).sort();
}

function suggestionOf(engine, device) {
  if (!engine.opts || engine.opts.classSuggest !== true || !device.classScores) return null;
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

function incidentAt(engine, device, ts) {
  const incident = device.incident;
  if (!incident || typeof incident.lastTs !== 'number') return null;
  const windowMs =
    engine.opts && typeof engine.opts.incidentWindowMs === 'number'
      ? engine.opts.incidentWindowMs
      : WINDOW_MS;
  if (ts < incident.firstTs || ts - incident.lastTs > windowMs) return null;
  return {
    id: incident.id,
    severity: incident.severity,
    firstTs: incident.firstTs,
    lastTs: incident.lastTs,
    detectors: (incident.detectors || []).slice(0, 16),
  };
}

function viewOf(engine, device, ts, source) {
  const cap = listCap(engine);
  const destinationState = device.states && device.states.get('new-destination');
  const familyState = device.states && device.states.get('new-domain-family');
  const portState = device.states && device.states.get('new-port');
  const quality = typeof engine._quality === 'function' ? engine._quality(device) : null;
  return {
    device: device.id,
    ts,
    source,
    mode: device.mode,
    suggestion: suggestionOf(engine, device),
    destinations: stringsOf(destinationState, 'dsts').slice(0, cap),
    families: stringsOf(familyState, 'families').slice(0, cap),
    ports: stringsOf(portState, 'ports').slice(0, cap),
    readiness: quality && quality.readiness ? quality.readiness : null,
    incident: incidentAt(engine, device, ts),
  };
}

/**
 * Device as the checkpoint knew it at ts. Does not emit.
 * @param {any} engine
 * @param {string} deviceId
 * @param {number} ts
 * @param {{ checkpoint?: object, log?: object[] }} [opts]
 */
function atOf(engine, deviceId, ts, opts = {}) {
  if (badDevice(deviceId)) throw new HubvikError('AT_DEVICE_IS_INVALID', 'device id is invalid');
  if (badTime(ts)) throw new HubvikError('AT_TS_IS_INVALID', 'at ts is invalid');
  const log = opts && opts.log;
  if (log != null && !Array.isArray(log)) {
    throw new HubvikError('AT_LOG_IS_INVALID', 'at log is invalid');
  }
  if (!log) {
    const found = findDevice(engine, deviceId);
    if (!found) throw new HubvikError('AT_DEVICE_IS_UNKNOWN', 'at device is unknown');
    if (typeof found.device.lastTs === 'number' && found.device.lastTs > ts) {
      throw new HubvikError('AT_LOG_IS_REQUIRED', 'at log is required');
    }
    return viewOf(found.owner, found.device, ts, 'checkpoint');
  }
  const checkpoint = opts.checkpoint;
  if (checkpoint != null && (typeof checkpoint !== 'object' || Array.isArray(checkpoint))) {
    throw new HubvikError('AT_CHECKPOINT_IS_INVALID', 'at checkpoint is invalid');
  }
  const { createEngine } = require('./engine');
  const box = createEngine(rawOpts(engine));
  copyDetectors(engine, box);
  if (checkpoint) box.restore(checkpoint);
  for (const event of log) {
    if (!event || typeof event.ts !== 'number' || event.ts > ts) continue;
    box.feed(event);
  }
  const found = findDevice(box, deviceId);
  if (!found) throw new HubvikError('AT_DEVICE_IS_UNKNOWN', 'at device is unknown');
  return viewOf(found.owner, found.device, ts, 'checkpoint+log');
}

function memberList(record, detectorId, key) {
  const block = record && record.detectors && record.detectors[detectorId];
  const list = block && block.state && block.state[key];
  if (!Array.isArray(list)) return [];
  return list.map((item) => String(item));
}

function suggestionNames(record) {
  if (!record || !Array.isArray(record.suggestions)) return [];
  const names = [];
  for (const row of record.suggestions) {
    if (typeof row === 'string') names.push(row);
    else if (row && typeof row.class === 'string') names.push(row.class);
  }
  return names;
}

function delta(before, after) {
  const oldSet = new Set(before);
  const newSet = new Set(after);
  return {
    appeared: [...newSet].filter((item) => !oldSet.has(item)).sort(),
    disappeared: [...oldSet].filter((item) => !newSet.has(item)).sort(),
  };
}

function devicesOf(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || !body.devices) {
    throw new HubvikError('DIFF_BASELINE_IS_INVALID', 'baseline is invalid');
  }
  if (typeof body.devices !== 'object' || Array.isArray(body.devices)) {
    throw new HubvikError('DIFF_BASELINE_IS_INVALID', 'baseline is invalid');
  }
  return body.devices;
}

/**
 * Destinations, families, ports, and class suggestions that appeared or disappeared.
 * Does not emit.
 * @param {object} before
 * @param {object} after
 */
function diffBaselineOf(before, after) {
  const left = devicesOf(before);
  const right = devicesOf(after);
  const ids = [...new Set([...Object.keys(left), ...Object.keys(right)])].sort();
  const devices = [];
  for (const id of ids) {
    if (FORBIDDEN_KEYS.has(id)) {
      throw new HubvikError('DIFF_BASELINE_IS_INVALID', 'baseline is invalid');
    }
    const a = left[id] || {};
    const b = right[id] || {};
    devices.push({
      device: id,
      destinations: delta(
        memberList(a, 'new-destination', 'dsts'),
        memberList(b, 'new-destination', 'dsts'),
      ),
      families: delta(
        memberList(a, 'new-domain-family', 'families'),
        memberList(b, 'new-domain-family', 'families'),
      ),
      ports: delta(memberList(a, 'new-port', 'ports'), memberList(b, 'new-port', 'ports')),
      suggestions: delta(suggestionNames(a), suggestionNames(b)),
    });
  }
  return { devices };
}

function copyDetectors(engine, box) {
  const registry =
    engine.registry || (engine.engines && engine.engines[0] && engine.engines[0].registry) || [];
  const known = new Set(box.registry.map((det) => det.id));
  for (const det of registry) {
    if (!known.has(det.id)) box.use(det);
  }
}

function play(engine, device, destination, events, learn) {
  const { createEngine } = require('./engine');
  const box = createEngine(rawOpts(engine));
  copyDetectors(engine, box);
  box.importBaseline(engine.exportBaseline({ createdAt: 0 }));
  if (learn) {
    if (!box.devices.has(device)) box._touch(device, 0);
    box.allow(device, 'dst', destination);
  }
  /** @type {any[]} */
  const alerts = [];
  box.on('anomaly', (item) => {
    if (item && item.device === device) alerts.push(item);
  });
  for (const event of events) box.feed(event);
  return alerts;
}

/**
 * Alerts that stay quiet when destination is already learned. The live engine is not fed.
 * @param {any} engine
 * @param {string} device
 * @param {string} destination
 * @param {object[]} events
 */
function withoutOf(engine, device, destination, events) {
  if (badDevice(device)) throw new HubvikError('WITHOUT_DEVICE_IS_INVALID', 'device id is invalid');
  if (typeof destination !== 'string' || destination.length === 0 || destination.length > 255) {
    throw new HubvikError('WITHOUT_DESTINATION_IS_INVALID', 'without destination is invalid');
  }
  if (!Array.isArray(events)) {
    throw new HubvikError('WITHOUT_EVENTS_ARE_INVALID', 'without events are invalid');
  }
  const plain = play(engine, device, destination, events, false);
  const learned = new Set(
    play(engine, device, destination, events, true).map(
      (item) => `${item.detector}\0${item.ts}\0${item.actual}`,
    ),
  );
  const quiet = [];
  for (const item of plain) {
    const key = `${item.detector}\0${item.ts}\0${item.actual}`;
    if (learned.has(key)) continue;
    quiet.push({ detector: item.detector, ts: item.ts, actual: item.actual });
  }
  quiet.sort((a, b) => a.ts - b.ts || (a.detector < b.detector ? -1 : 1));
  return { device, destination, quiet: quiet.slice(0, listCap(engine)) };
}

function hostFacts(engine) {
  /** @type {any[]} */
  const rows = [];
  eachEngine(engine, (owner) => {
    if (Array.isArray(owner._hostFacts)) rows.push(...owner._hostFacts);
  });
  return rows;
}

function findIncident(engine, id) {
  let found = null;
  eachEngine(engine, (owner) => {
    if (found || !owner.devices) return;
    for (const device of owner.devices.values()) {
      if (device.incident && device.incident.id === id) found = device.incident;
    }
  });
  return found;
}

/**
 * One paragraph from alerts already stored. Does not open a file and does not emit.
 * @param {any} engine
 * @param {string} incidentId
 */
function storyOf(engine, incidentId) {
  if (typeof incidentId !== 'string' || incidentId.length === 0) {
    throw new HubvikError('STORY_INCIDENT_IS_INVALID', 'story incident is invalid');
  }
  const incident = findIncident(engine, incidentId);
  if (!incident) throw new HubvikError('STORY_INCIDENT_IS_INVALID', 'story incident is invalid');
  const facts = hostFacts(engine)
    .filter((row) => row.device === incident.device && row.ts <= incident.firstTs)
    .sort((a, b) => a.ts - b.ts || (a.type < b.type ? -1 : 1) || (a.name < b.name ? -1 : 1));
  const lines = Array.isArray(incident.lines) ? incident.lines : [];
  let text = `${incident.device} from ${incident.firstTs} to ${incident.lastTs}: ${lines.join('; ')}.`;
  if (facts[0]) {
    text = `Earliest host fact: ${facts[0].type} ${facts[0].name} at ${facts[0].ts}. ${text}`;
  }
  return { incident: incident.id, text };
}

/**
 * Canned attacks on a throwaway copy of the live baseline. The live engine emits nothing.
 * @param {any} engine
 */
function drillOf(engine) {
  const { createEngine } = require('./engine');
  const box = createEngine(rawOpts(engine));
  copyDetectors(engine, box);
  box.importBaseline(engine.exportBaseline({ createdAt: 0 }));
  return runScenarios(box, {});
}

const pastMethods = {
  /** @this {any} @param {string} device @param {number} ts @param {{ checkpoint?: object, log?: object[] }} [opts] */
  at(device, ts, opts) {
    return atOf(this, device, ts, opts);
  },
  /** @this {any} @param {object} before @param {object} after */
  diffBaseline(before, after) {
    return diffBaselineOf(before, after);
  },
  /** @this {any} @param {string} device @param {string} destination @param {object[]} events */
  without(device, destination, events) {
    return withoutOf(this, device, destination, events);
  },
  /** @this {any} @param {string} incidentId */
  story(incidentId) {
    return storyOf(this, incidentId);
  },
  /** @this {any} */
  drill() {
    return drillOf(this);
  },
};

module.exports = { pastMethods };
