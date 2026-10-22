'use strict';

const { HubvikError } = require('../../errors');

const { normalizeName, requireFields, num } = require('./common');

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function summaryEvent(raw, ts, warnings) {
  /** @type {Record<string, any>} */
  const event = { type: 'summary', tier: 'T0', device: raw.device, ts, bytes: 0 };
  if (raw.dst != null) {
    const dst = normalizeName(raw.dst, 255);
    if (dst) event.dst = dst;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped event.dst' });
  }
  if (raw.bytes != null) {
    if (typeof raw.bytes === 'number' && Number.isFinite(raw.bytes) && raw.bytes >= 0) {
      event.bytes = raw.bytes;
    } else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped event.bytes' });
  }
  return event;
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function flowEvent(raw, ts, warnings) {
  requireFields(
    raw,
    [
      'srcIp',
      'srcPort',
      'dstIp',
      'dstPort',
      'proto',
      'direction',
      'bytesOut',
      'bytesIn',
      'pktsOut',
      'pktsIn',
      'durationMs',
    ],
    'flow',
  );
  const direction = raw.direction;
  if (direction !== 'out' && direction !== 'in' && direction !== 'lan') {
    throw new HubvikError('FLOW_DIRECTION_IS_INVALID', 'flow direction is invalid');
  }
  const proto = raw.proto;
  const protoOk =
    proto === 'tcp' ||
    proto === 'udp' ||
    proto === 'icmp' ||
    proto === 'gre' ||
    proto === 'esp' ||
    (typeof proto === 'number' && proto >= 0);
  if (!protoOk) throw new HubvikError('FLOW_PROTO_IS_INVALID', 'flow proto is invalid');
  /** @type {Record<string, any>} */
  const event = {
    type: 'flow',
    tier: 'T1',
    device: raw.device,
    ts,
    srcIp: String(raw.srcIp),
    srcPort: num(raw.srcPort, 'srcPort', { integer: true, max: 65535 }),
    dstIp: String(raw.dstIp),
    dstPort: num(raw.dstPort, 'dstPort', { integer: true, max: 65535 }),
    proto,
    direction,
    bytesOut: num(raw.bytesOut, 'bytesOut'),
    bytesIn: num(raw.bytesIn, 'bytesIn'),
    pktsOut: num(raw.pktsOut, 'pktsOut'),
    pktsIn: num(raw.pktsIn, 'pktsIn'),
    durationMs: num(raw.durationMs, 'durationMs'),
  };
  if (raw.tcpOutcome != null) {
    const ok = ['established', 'rejected', 'no-response', 'reset'];
    if (ok.includes(raw.tcpOutcome)) event.tcpOutcome = raw.tcpOutcome;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.tcpOutcome' });
  }
  if (raw.icmpType != null) {
    if (Number.isInteger(raw.icmpType) && raw.icmpType >= 0 && raw.icmpType <= 255) {
      event.icmpType = raw.icmpType;
    } else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.icmpType' });
  }
  if (raw.ttl != null) {
    if (Number.isInteger(raw.ttl) && raw.ttl >= 0 && raw.ttl <= 255) event.ttl = raw.ttl;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.ttl' });
  }
  if (raw.dstName != null) {
    const name = normalizeName(raw.dstName, 255);
    if (name) event.dstName = name;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.dstName' });
  }
  const splt = flowSplt(raw.splt, warnings);
  if (splt) event.splt = splt;
  return event;
}

/**
 * @param {unknown} value
 * @param {{ code: string, message: string }[]} warnings
 * @returns {{ len: number[], iat: number[] } | null}
 */
function flowSplt(value, warnings) {
  if (value == null) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.splt' });
    return null;
  }
  const row = /** @type {any} */ (value);
  if (
    !Array.isArray(row.len) ||
    !Array.isArray(row.iat) ||
    row.len.length > 10 ||
    row.iat.length > 10
  ) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.splt' });
    return null;
  }
  /** @type {number[]} */
  const len = [];
  /** @type {number[]} */
  const iat = [];
  for (const item of row.len) {
    if (!Number.isInteger(item) || item < -65535 || item > 65535) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.splt' });
      return null;
    }
    len.push(item);
  }
  for (const item of row.iat) {
    if (!Number.isInteger(item) || item < 0 || item > 600000) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.splt' });
      return null;
    }
    iat.push(item);
  }
  return { len, iat };
}

module.exports = { summaryEvent, flowEvent };
