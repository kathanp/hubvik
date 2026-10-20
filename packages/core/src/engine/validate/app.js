'use strict';

const { requireFields, num, normalizeName } = require('./common');

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function httpEvent(raw, ts, warnings) {
  requireFields(raw, ['dstIp', 'dstPort', 'method'], 'http');
  /** @type {Record<string, any>} */
  const event = {
    type: 'http',
    tier: 'T3',
    device: raw.device,
    ts,
    dstIp: String(raw.dstIp),
    dstPort: num(raw.dstPort, 'dstPort', { integer: true, max: 65535 }),
    method: String(raw.method).slice(0, 32),
  };
  if (raw.host != null) {
    const host = normalizeName(raw.host, 255);
    if (host) event.host = host;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped http.host' });
  }
  if (typeof raw.path === 'string') event.path = raw.path.slice(0, 255);
  if (raw.status != null) {
    if (Number.isInteger(raw.status) && raw.status >= 100 && raw.status <= 599) {
      event.status = raw.status;
    } else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped http.status' });
  }
  if (raw.direction != null) {
    if (raw.direction === 'out' || raw.direction === 'in') event.direction = raw.direction;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped http.direction' });
  }
  return event;
}

const APP_PROTOS = new Set([
  'bacnet',
  'modbus',
  'dnp3',
  'knx',
  's7',
  'enip',
  'mqtt',
  'coap',
  'rtsp',
  'onvif',
  'stratum',
  'smtp',
  'upnp',
  'matter',
]);

/**
 * Host-reported UPnP, NAT-PMP, or PCP mapping.
 * @param {any} raw
 * @param {number} ts
 */
function mappingEvent(raw, ts) {
  requireFields(raw, ['proto', 'port'], 'mapping');
  if (raw.proto !== 'upnp' && raw.proto !== 'nat-pmp' && raw.proto !== 'pcp') {
    throw new TypeError('mapping proto is invalid');
  }
  /** @type {Record<string, any>} */
  const event = {
    type: 'mapping',
    tier: 'T1',
    device: raw.device,
    ts,
    proto: raw.proto,
    port: num(raw.port, 'port', { integer: true, max: 65535 }),
  };
  if (raw.externalPort != null) {
    event.externalPort = num(raw.externalPort, 'externalPort', { integer: true, max: 65535 });
  }
  return event;
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function appEvent(raw, ts, warnings) {
  requireFields(raw, ['proto', 'role', 'peerIp', 'op'], 'app');
  if (!APP_PROTOS.has(raw.proto)) throw new TypeError('app proto is invalid');
  if (raw.role !== 'client' && raw.role !== 'server') throw new TypeError('app role is invalid');
  /** @type {Record<string, any>} */
  const event = {
    type: 'app',
    tier: 'T5',
    device: raw.device,
    ts,
    proto: raw.proto,
    role: raw.role,
    peerIp: String(raw.peerIp),
    op: String(raw.op).slice(0, 255),
  };
  if (raw.target != null) event.target = String(raw.target).slice(0, 255);
  if (typeof raw.value === 'number' || typeof raw.value === 'string') event.value = raw.value;
  else if (raw.value != null)
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped app.value' });
  if (raw.result === 'ok' || raw.result === 'error' || raw.result === 'reject')
    event.result = raw.result;
  return event;
}

module.exports = { httpEvent, mappingEvent, appEvent };
