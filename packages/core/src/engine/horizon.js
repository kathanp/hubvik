'use strict';

const { HubvikError } = require('../errors');

const { createHll, add, toJSON, fromJSON } = require('./stats/hll');

const HOUR = 3600e3;
const DAY = 24 * HOUR;
const RING = 24;

/**
 * @param {any} engine
 * @returns {boolean}
 */
function horizonOn(engine) {
  if (!engine.opts.tiers.includes('T1')) return false;
  if (engine.opts.horizons === false) return false;
  if (engine.opts.horizons === true) return true;
  return ['slow-scan', 'multi-horizon-exfil'].some((id) => {
    const status = engine.detectorStatus[id];
    return status && status.active;
  });
}

/**
 * @param {number} hour
 */
function blank(hour) {
  return { hour, bytesOut: 0, bytesIn: 0, flows: 0, newPairsHll: createHll({ p: 8 }) };
}

/**
 * @param {any} device
 */
function ringOf(device) {
  if (!device.horizon) device.horizon = { rows: [], open: null, lastTs: null };
  return device.horizon;
}

/**
 * Count one flow into the open hour. A gap over 24 h clears the ring and is not an alert.
 * @param {any} device
 * @param {any} event
 * @returns {void}
 */
function noteHorizon(device, event) {
  if (!event || event.type !== 'flow' || typeof event.ts !== 'number') return;
  const ring = ringOf(device);
  if (ring.lastTs != null && event.ts - ring.lastTs > DAY) {
    ring.rows = [];
    ring.open = null;
  }
  ring.lastTs = event.ts;
  const hour = Math.floor(event.ts / HOUR);
  if (!ring.open || ring.open.hour !== hour) {
    if (ring.open && ring.open.hour < hour) commit(ring, ring.open);
    ring.open = blank(hour);
  }
  ring.open.bytesOut += Number(event.bytesOut) || 0;
  ring.open.bytesIn += Number(event.bytesIn) || 0;
  ring.open.flows += 1;
}

/**
 * Close an hour when a later window closes. Uses the window start, which comes from event time.
 * @param {any} device
 * @param {number} windowStart
 * @returns {void}
 */
function rollHorizon(device, windowStart) {
  const ring = device.horizon;
  if (!ring || !ring.open || typeof windowStart !== 'number') return;
  const hour = Math.floor(windowStart / HOUR);
  if (ring.open.hour < hour) {
    commit(ring, ring.open);
    ring.open = null;
  }
}

/**
 * @param {any} ring
 * @param {any} row
 */
function commit(ring, row) {
  ring.rows.push(row);
  while (ring.rows.length > RING) ring.rows.shift();
}

/**
 * @param {any} ring
 * @param {number} hours
 */
function rowsOf(ring, hours) {
  const kept = [];
  if (ring) {
    for (const row of ring.rows) kept.push(row);
    if (ring.open) kept.push(ring.open);
  }
  const n = Number.isInteger(hours) ? Math.max(0, Math.min(RING, hours)) : 0;
  return kept.slice(-n);
}

/**
 * Read-only view. `addPair` is how slow-scan records a pair that is not in the learned set.
 * @param {any} device
 */
function horizonView(device) {
  return {
    /**
     * @param {number} hours
     */
    last(hours) {
      return rowsOf(device.horizon, hours).map((row) => ({
        hour: row.hour,
        bytesOut: row.bytesOut,
        bytesIn: row.bytesIn,
        flows: row.flows,
        newPairsHll: row.newPairsHll,
      }));
    },
    /**
     * @param {string} field
     * @param {number} hours
     */
    sum(field, hours) {
      if (field === 'newPairsHll') return 0;
      let total = 0;
      for (const row of rowsOf(device.horizon, hours)) {
        const value = row[field];
        if (typeof value === 'number') total += value;
      }
      return total;
    },
    /**
     * @param {string} key
     */
    addPair(key) {
      const ring = device.horizon;
      if (!ring || !ring.open || typeof key !== 'string' || key.length === 0) return;
      add(ring.open.newPairsHll, key);
    },
  };
}

/**
 * @param {any} row
 */
function exportRow(row) {
  if (!row) return null;
  return {
    hour: row.hour,
    bytesOut: row.bytesOut,
    bytesIn: row.bytesIn,
    flows: row.flows,
    newPairsHll: toJSON(row.newPairsHll),
  };
}

/**
 * @param {any} device
 */
function exportHorizon(device) {
  const ring = device.horizon;
  if (!ring) return null;
  return {
    lastTs: ring.lastTs,
    open: exportRow(ring.open),
    rows: ring.rows.map(exportRow),
  };
}

/**
 * @param {any} raw
 */
function importRow(raw) {
  if (!raw || typeof raw !== 'object')
    throw new HubvikError('CHECKPOINT_HORIZON_IS_INVALID', 'checkpoint horizon is invalid');
  if (typeof raw.hour !== 'number' || typeof raw.bytesOut !== 'number') {
    throw new HubvikError('CHECKPOINT_HORIZON_IS_INVALID', 'checkpoint horizon is invalid');
  }
  return {
    hour: raw.hour,
    bytesOut: raw.bytesOut,
    bytesIn: typeof raw.bytesIn === 'number' ? raw.bytesIn : 0,
    flows: typeof raw.flows === 'number' ? raw.flows : 0,
    newPairsHll: fromJSON(raw.newPairsHll),
  };
}

/**
 * @param {any} device
 * @param {any} raw
 */
function importHorizon(device, raw) {
  if (raw == null) return;
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.rows) || raw.rows.length > RING) {
    throw new HubvikError('CHECKPOINT_HORIZON_IS_INVALID', 'checkpoint horizon is invalid');
  }
  device.horizon = {
    lastTs: typeof raw.lastTs === 'number' ? raw.lastTs : null,
    open: raw.open ? importRow(raw.open) : null,
    rows: raw.rows.map(importRow),
  };
}

module.exports = {
  horizonOn,
  noteHorizon,
  rollHorizon,
  horizonView,
  exportHorizon,
  importHorizon,
};
