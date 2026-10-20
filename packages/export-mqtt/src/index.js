'use strict';

/**
 * Topic and payload pairs. The caller publishes them.
 * @param {any} record
 * @returns {{ topic: string, payload: string }[]}
 */
function toMessages(record) {
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
    return [{ topic: `iotwarden/campaign/${row.id}`, payload: body }];
  }
  if (Array.isArray(row.anomalyIds)) {
    return [{ topic: `iotwarden/incident/${row.device || 'unknown'}`, payload: body }];
  }
  return [
    {
      topic: `iotwarden/anomaly/${row.device || 'unknown'}/${row.detector || 'unknown'}`,
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

module.exports = { toMessages, publishWith };
