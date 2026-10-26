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
    return [{ topic: `hubvik/campaign/${topicPart(row.id, 'unknown')}`, payload: body }];
  }
  if (Array.isArray(row.anomalyIds)) {
    return [{ topic: `hubvik/incident/${topicPart(row.device, 'unknown')}`, payload: body }];
  }
  const device = topicPart(row.device, 'unknown');
  const detector = topicPart(row.detector, 'unknown');
  return [{ topic: `hubvik/anomaly/${device}/${detector}`, payload: body }];
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
 * One MQTT topic level. `#`, `+`, `/`, and controls are removed so a device name
 * cannot add a level or a wildcard.
 * @param {unknown} value
 * @param {string} fallback
 * @returns {string}
 */
function topicPart(value, fallback) {
  const raw = value == null || value === '' ? fallback : String(value);
  let out = '';
  for (const ch of raw) {
    const code = ch.codePointAt(0);
    if (code == null || code <= 32 || code === 127 || ch === '#' || ch === '+' || ch === '/')
      continue;
    out += ch;
    if (out.length >= 128) break;
  }
  return out || fallback;
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
