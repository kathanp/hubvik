'use strict';

const PRI = { critical: 2, high: 3, medium: 4, low: 5, info: 6 };
const CEF = { critical: 10, high: 8, medium: 5, low: 3, info: 1 };

/**
 * Format one anomaly as an RFC 5424 line whose message is a CEF record.
 * Facility is local0 (16).
 * @param {{ id?: string, device?: string, detector?: string, severity?: string, ts?: number, actual?: string, expected?: string }} anomaly
 * @param {{ host?: string, app?: string }} [opts]
 */
function format(anomaly, opts = {}) {
  if (opts.alertsOnly && !isAlert(anomaly)) return '';
  const severity = anomaly && PRI[anomaly.severity] != null ? anomaly.severity : 'info';
  const pri = 16 * 8 + PRI[severity];
  const ts = anomaly && typeof anomaly.ts === 'number' ? anomaly.ts : 0;
  const host = opts.host || '-';
  const app = opts.app || 'hubvik';
  const detector = anomaly && anomaly.detector ? sanitize(anomaly.detector) : '-';
  const cef = [
    'CEF:0',
    'hubvik',
    'hubvik',
    '0.1.0',
    detector,
    sanitize(anomaly && anomaly.actual ? anomaly.actual : detector),
    String(CEF[severity]),
    `cs1Label=device cs1=${sanitize(anomaly && anomaly.device ? anomaly.device : '')}`,
    `msg=${sanitize(anomaly && anomaly.expected ? anomaly.expected : '')}`,
  ].join('|');
  return `<${pri}>1 ${new Date(ts).toISOString()} ${sanitize(host)} ${sanitize(app)} - ${detector} - ${cef}`;
}

/**
 * @param {string} value
 */
function sanitize(value) {
  return String(value)
    .replace(/[\r\n|]/g, ' ')
    .slice(0, 512);
}

/**
 * @param {any} row
 */
function isAlert(row) {
  return (
    row &&
    (row.kind === 'incident' ||
      row.kind === 'hard-rule' ||
      row.kind === 'campaign' ||
      row.kind === 'digest')
  );
}

module.exports = { format };
