'use strict';

const { wilson } = require('./protocol.js');

/**
 * C6.3 gate as false positives per benign device-day. Info and low have none.
 * @param {string} severity
 * @returns {number | null}
 */
function gatePerDay(severity) {
  if (severity === 'medium') return 1;
  if (severity === 'high' || severity === 'critical') return 1 / 7;
  return null;
}

/**
 * @param {number} falsePositives
 * @param {number} days
 * @returns {number}
 */
function fpRate(falsePositives, days) {
  if (!(days > 0)) return falsePositives > 0 ? Number.POSITIVE_INFINITY : 0;
  return falsePositives / days;
}

/**
 * @param {{ exercised?: boolean, unique?: number, falsePositives?: number, severity?: string }} row
 * @param {number} days
 * @returns {'keep' | 'review' | 'propose-demote' | 'no-data'}
 */
function suggestion(row, days) {
  if (!row.exercised) return 'no-data';
  const unique = row.unique || 0;
  const under = underGate(row.severity || '', fpRate(row.falsePositives || 0, days));
  if (unique >= 1 && under) return 'keep';
  if (unique === 0 && !under) return 'propose-demote';
  return 'review';
}

/**
 * @param {string} severity
 * @param {number} rate
 * @returns {boolean}
 */
function underGate(severity, rate) {
  const gate = gatePerDay(severity);
  if (gate == null) return true;
  return rate < gate;
}

/**
 * @param {number} falsePositives
 * @param {number} days
 * @returns {{ low: number, high: number } | null}
 */
function fpWilson(falsePositives, days) {
  if (!(days > 0) || falsePositives > days) return null;
  return wilson(falsePositives, days);
}

/**
 * @param {any} result
 * @param {string} split
 * @param {Map<string, { mode: string, hardRule: boolean }>} registry
 * @returns {any[]}
 */
function rowsFromResult(result, split, registry) {
  const days = Number(result.benignDeviceDays) || 0;
  const attacks = Number(result.attackInstances) || 0;
  /** @type {Map<string, number>} */
  const fires = new Map();
  for (const hit of result.hits || []) {
    for (const id of hit.detectors || []) fires.set(id, (fires.get(id) || 0) + 1);
  }
  return (result.ablation || []).map((row) => {
    const meta = registry.get(row.detector) || { mode: 'live', hardRule: false };
    const fp = row.falsePositives || 0;
    return {
      id: row.detector,
      mode: meta.mode,
      hardRule: meta.hardRule,
      fires: (fires.get(row.detector) || 0) + fp,
      uniqueDetections: row.unique || 0,
      falsePositives: fp,
      benignDeviceDays: days,
      fpPerBenignDeviceDay: days > 0 ? fp / days : null,
      wilson95: fpWilson(fp, days),
      split,
      suggestion: suggestion(row, days),
      nTooSmall: attacks < 20,
    };
  });
}

module.exports = { gatePerDay, suggestion, rowsFromResult, fpWilson };
