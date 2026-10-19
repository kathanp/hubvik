'use strict';

const { domainFamily } = require('./net');
const { isGroupDst } = require('../detectors/lib');
const { CLASSES } = require('./classes');

const DAY = 24 * 60 * 60 * 1000;
const CAP = 500;
const VALUE_BLOCK = new Set(['threat-intel-match', 'proxy-sdk-traffic', 'tor-or-proxy']);

/**
 * Destination family, port, JA4, and resolver. Hard rules, OT writes, and
 * cert-change are not in this table, so they are never promoted.
 * @type {Record<string, { kind: string, value: (ev: any) => string | null, known: (state: any, value: string) => boolean }>}
 */
const TRACK = {
  'new-domain-family': {
    kind: 'dst',
    value(ev) {
      return ev.dst ? domainFamily(ev.dst) : null;
    },
    known(state, value) {
      return Boolean(state.families && state.families.has(value));
    },
  },
  'new-port': {
    kind: 'port',
    value(ev) {
      if (ev.type !== 'flow' || ev.dstPort == null || ev.direction == null) return null;
      if (isGroupDst(ev.dstIp)) return null;
      return `${ev.direction}:${ev.dstPort}`;
    },
    known(state, value) {
      return Boolean(state.ports && state.ports.has(value));
    },
  },
  'new-client-fingerprint': {
    kind: 'ja4',
    value(ev) {
      return ev.type === 'tls' && ev.ja4 ? ev.ja4 : null;
    },
    known(state, value) {
      return Boolean(state.seen && state.seen.has(value));
    },
  },
  'resolver-bypass': {
    kind: 'resolver',
    value(ev) {
      if (ev.type === 'dns' && ev.resolver) return ev.resolver;
      if (ev.type === 'flow' && ev.dstPort === 53 && ev.dstIp) return ev.dstIp;
      return null;
    },
    known(state, value) {
      return Boolean(state.resolvers && state.resolvers.has(value));
    },
  },
};

/**
 * A value listed on the device class is an expectation, not a candidate.
 * @param {any} device
 * @param {string} value
 * @returns {boolean}
 */
function classExpects(device, value) {
  const spec = device.deviceClass ? CLASSES[device.deviceClass] : null;
  if (!spec) return false;
  for (const item of Object.values(spec)) {
    if (Array.isArray(item) && item.includes(value)) return true;
  }
  return false;
}

/**
 * @param {any} device
 * @param {string} detectorId
 * @returns {Map<string, { days: Set<number>, hits: number }>}
 */
function tableOf(device, detectorId) {
  if (!device.promote) device.promote = new Map();
  let table = device.promote.get(detectorId);
  if (!table) {
    table = new Map();
    device.promote.set(detectorId, table);
  }
  return table;
}

/**
 * Record a high-or-above anomaly, a hard-rule anomaly, or a value hit that blocks promotion.
 * @param {any} engine
 * @param {any} device
 * @param {any} det
 * @param {any} anomaly
 * @returns {void}
 */
function noteThreat(engine, device, det, anomaly) {
  if (!engine.opts.promote) return;
  const high = anomaly.severity === 'high' || anomaly.severity === 'critical';
  if (high || det.hardRule) {
    if (!device.badDays) device.badDays = new Set();
    device.badDays.add(Math.floor(anomaly.ts / DAY));
  }
  if (VALUE_BLOCK.has(det.id)) {
    if (!device.blockedValues) device.blockedValues = new Set();
    device.blockedValues.add(String(anomaly.actual));
  }
}

/**
 * @param {any} device
 * @param {{ days: Set<number> }} row
 * @param {string} value
 * @returns {boolean}
 */
function poisoned(device, row, value) {
  if (device.blockedValues && device.blockedValues.has(value)) return true;
  if (!device.badDays) return false;
  for (const day of row.days) {
    if (device.badDays.has(day)) return true;
  }
  return false;
}

/**
 * Count a watched value and promote it into the baseline when the cap is met.
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @returns {void}
 */
function noteWatch(engine, device, event) {
  const spec = engine.opts.promote;
  if (!spec || device.mode !== 'watching') return;
  for (const id of Object.keys(TRACK)) {
    const det = engine.byId.get(id);
    const status = engine.detectorStatus[id];
    if (!det || det.hardRule || !status || !status.active || typeof det.allow !== 'function') {
      continue;
    }
    const track = TRACK[id];
    const value = track.value(event);
    if (!value || classExpects(device, value)) continue;
    const state = engine._state(device, det);
    const table = tableOf(device, id);
    if (track.known(state, value)) {
      table.delete(value);
      continue;
    }
    let row = table.get(value);
    if (row) {
      table.delete(value);
    } else {
      while (table.size >= CAP) {
        const oldest = table.keys().next().value;
        if (oldest == null) break;
        table.delete(oldest);
      }
      row = { days: new Set(), hits: 0 };
    }
    table.set(value, row);
    row.days.add(Math.floor(event.ts / DAY));
    row.hits += 1;
    if (row.hits < spec.minHits || row.days.size < spec.afterDays) continue;
    if (poisoned(device, row, value)) {
      table.delete(value);
      continue;
    }
    if (!det.allow(state, track.kind, value)) continue;
    table.delete(value);
    engine._warn('BASELINE_PROMOTED', 'a watched value joined the baseline', device.id, {
      detector: id,
      value,
      ts: event.ts,
    });
  }
}

module.exports = { noteThreat, noteWatch, CAP };
