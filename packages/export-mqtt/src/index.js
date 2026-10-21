'use strict';

/**
 * Topic and payload pairs. The caller publishes them.
 * @param {any} record
 * @returns {{ topic: string, payload: string }[]}
 */
function toMessages(record, opts = {}) {
  if (opts && opts.alertsOnly && !isAlert(record)) return [];
  const row = record || {};
  const body = JSON.stringify({
    id: row.id || '',
    detector: row.detector || '',
    severity: row.severity || 'info',
    ts: row.ts || 0,
    device: row.device || null,
    devices: row.devices || null,
  });
  if (Array.isArray(row.devices) && row.id) {
    return [{ topic: `hubvik/campaign/${row.id}`, payload: body }];
  }
  if (Array.isArray(row.anomalyIds)) {
    return [{ topic: `hubvik/incident/${row.device || 'unknown'}`, payload: body }];
  }
  return [
    {
      topic: `hubvik/anomaly/${row.device || 'unknown'}/${row.detector || 'unknown'}`,
      payload: body,
    },
  ];
}

/**
 * @param {(topic: string, payload: string) => void} publish
 * @param {any} record
 */
function publishWith(publish, record) {
  const messages = toMessages(record);
  for (const message of messages) publish(message.topic, message.payload);
  return messages.length;
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

module.exports = { toMessages, publishWith };
