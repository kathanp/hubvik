'use strict';

const OUTCOME = {
  SF: 'established',
  S1: 'established',
  S2: 'established',
  S3: 'established',
  REJ: 'rejected',
  S0: 'no-response',
  SH: 'no-response',
  SHR: 'no-response',
  OTH: 'no-response',
  RSTO: 'reset',
  RSTR: 'reset',
  RSTOS0: 'reset',
  RSTRH: 'reset',
};

/**
 * Zeek `conn_state` for TCP. Other protocols omit the field.
 * @param {unknown} proto
 * @param {unknown} state
 * @returns {'established' | 'rejected' | 'no-response' | 'reset' | undefined}
 */
function tcpOutcome(proto, state) {
  if (String(proto || 'tcp').toLowerCase() !== 'tcp') return undefined;
  if (typeof state !== 'string') return undefined;
  return OUTCOME[state];
}

/**
 * Which address is the device, and whether the flow is outbound, inbound, or on the LAN.
 * `local_orig` and `local_resp` win. Otherwise private addresses decide.
 * `bytesOut` stays the device's bytes: inbound swaps Zeek's orig and resp counters.
 * @param {any} row
 * @param {string} src
 * @param {string} dst
 * @returns {{ deviceIp: string, direction: 'out' | 'in' | 'lan', inbound: boolean }}
 */
function flowSide(row, src, dst) {
  if (row.local_orig === true && row.local_resp === true) {
    return { deviceIp: src, direction: 'lan', inbound: false };
  }
  if (row.local_orig === true) return { deviceIp: src, direction: 'out', inbound: false };
  if (row.local_resp === true) return { deviceIp: dst, direction: 'in', inbound: true };
  return addressSide(src, dst);
}

/**
 * @param {string} src
 * @param {string} dst
 * @returns {{ deviceIp: string, direction: 'out' | 'in' | 'lan', inbound: boolean }}
 */
function addressSide(src, dst) {
  const srcLocal = isLocalAddress(src);
  const dstLocal = isLocalAddress(dst);
  if (srcLocal && dstLocal) return { deviceIp: src, direction: 'lan', inbound: false };
  if (dstLocal && !srcLocal) return { deviceIp: dst, direction: 'in', inbound: true };
  return { deviceIp: src || dst, direction: 'out', inbound: false };
}

/**
 * Copy Zeek's connection uid when it is a short string.
 * @param {Record<string, any>} event
 * @param {any} row
 * @returns {Record<string, any>}
 */
function stamp(event, row) {
  if (typeof row.uid === 'string' && row.uid.length > 0 && row.uid.length <= 64) {
    event.uid = row.uid;
  }
  return event;
}

/**
 * One answer per Zeek `answers` entry. The query type is the answer type.
 * @param {any} row
 * @returns {{ type: string, value: string, ttl: number }[]}
 */
function dnsAnswers(row) {
  const values = Array.isArray(row.answers) ? row.answers : [];
  const ttls = Array.isArray(row.TTLs) ? row.TTLs : [];
  const type = String(row.qtype_name || 'A');
  return values.map((/** @type {unknown} */ value, /** @type {number} */ index) => ({
    type,
    value: String(value),
    ttl: Number(ttls[index] != null ? ttls[index] : row.TTLs) || 0,
  }));
}

/**
 * Modbus unit id and MQTT retain / will flags. Absent fields stay absent.
 * @param {string} log
 * @param {any} row
 * @returns {{ unitId?: number, flags?: string[], target?: string }}
 */
function appExtras(log, row) {
  /** @type {{ unitId?: number, flags?: string[], target?: string }} */
  const extra = {};
  if (log === 'modbus') {
    const unit = Number.isInteger(row.unit_id) ? row.unit_id : row.unit;
    if (Number.isInteger(unit)) extra.unitId = unit;
  }
  if (log === 'mqtt_publish' && row.retain === true) extra.flags = ['retain'];
  if (log === 'mqtt_connect' && row.will_topic) {
    extra.flags = ['will'];
    extra.target = String(row.will_topic).slice(0, 255);
  }
  return extra;
}

/**
 * Private, loopback, link-local, and IPv6 ULA addresses.
 * @param {string} ip
 * @returns {boolean}
 */
function isLocalAddress(ip) {
  if (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip.startsWith('169.254.')
  ) {
    return true;
  }
  const part = /^172\.(\d+)\./.exec(ip);
  if (part) {
    const octet = Number(part[1]);
    if (octet >= 16 && octet <= 31) return true;
  }
  const lower = ip.toLowerCase();
  return lower.startsWith('fe80:') || lower.startsWith('fc') || lower.startsWith('fd');
}

module.exports = { tcpOutcome, flowSide, stamp, dnsAnswers, appExtras };
