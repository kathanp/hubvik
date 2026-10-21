'use strict';

/**
 * One Elastic Common Schema document for an anomaly, incident, or campaign.
 * @param {any} record
 */
function toDocument(record, opts = {}) {
  if (opts.alertsOnly && !isAlert(record)) return null;
  const row = record || {};
  const ts =
    typeof row.ts === 'number' ? new Date(row.ts).toISOString() : '1970-01-01T00:00:00.000Z';
  /** @type {Record<string, unknown>} */
  const doc = {
    '@timestamp': ts,
    'ecs.version': '8.11.0',
    event: {
      kind: 'alert',
      dataset: 'hubvik',
      category: row.devices && row.edges ? ['intrusion_detection'] : ['network'],
      severity: row.severity || 'info',
    },
    message: row.actual || row.summary || '',
    observer: { name: 'hubvik' },
  };
  if (row.device) doc.host = { name: String(row.device) };
  if (Array.isArray(row.devices)) doc.related = { hosts: row.devices.map(String) };
  if (row.detector) doc.rule = { name: String(row.detector) };
  return doc;
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

module.exports = { toDocument };
