'use strict';

const { tcpOutcome, flowSide, stamp, dnsAnswers, appExtras } = require('./fields');

const LOGS = new Set([
  'conn',
  'dns',
  'ssl',
  'http',
  'modbus',
  'dnp3',
  'mqtt_connect',
  'mqtt_subscribe',
  'mqtt_publish',
  'bacnet',
  's7comm',
  'enip',
]);

/**
 * Parse one Zeek JSON log line into hubvik events.
 * `log` selects the Zeek path: conn, dns, ssl, http, modbus, dnp3,
 * mqtt_connect, mqtt_subscribe, mqtt_publish, or the ICSNPP logs bacnet, s7comm, enip.
 * @param {{ log?: string, device?: (ip: string) => string, now?: (ts: number) => number }} [opts]
 */
function createParser(opts = {}) {
  const log = opts.log || 'conn';
  if (!LOGS.has(log)) throw new TypeError('zeek log is invalid');
  const deviceFor = opts.device || ((ip) => ip);
  const now = opts.now || ((ts) => (typeof ts === 'number' ? Math.round(ts * 1000) : 0));
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      if (typeof line !== 'string' || line.length === 0 || line.startsWith('#')) return [];
      let row;
      try {
        row = JSON.parse(line);
      } catch {
        return [];
      }
      if (!row || typeof row !== 'object' || Array.isArray(row)) return [];
      const event = build(log, row, deviceFor, now);
      return event ? [event] : [];
    },
  };
}

/**
 * @param {string} log
 * @param {any} row
 * @param {(ip: string) => string} deviceFor
 * @param {(ts: number) => number} now
 */
function build(log, row, deviceFor, now) {
  const id = row.id && typeof row.id === 'object' ? row.id : {};
  const ts = now(typeof row.ts === 'number' ? row.ts : 0);
  if (log === 'conn') return flow(row, id, ts, deviceFor);
  if (log === 'dns') return dns(row, id, ts, deviceFor);
  if (log === 'ssl') return tls(row, id, ts, deviceFor);
  if (log === 'http') return http(row, id, ts, deviceFor);
  return application(log, row, id, ts, deviceFor);
}

/**
 * @param {any} row
 * @param {any} id
 * @param {number} ts
 * @param {(ip: string) => string} deviceFor
 */
function flow(row, id, ts, deviceFor) {
  if (!id.orig_h || !id.resp_h) return null;
  const src = String(id.orig_h);
  const dst = String(id.resp_h);
  const side = flowSide(row, src, dst);
  /** @type {Record<string, any>} */
  const event = {
    type: 'flow',
    device: deviceFor(side.deviceIp),
    ts,
    srcIp: src,
    srcPort: Number(id.orig_p) || 0,
    dstIp: dst,
    dstPort: Number(id.resp_p) || 0,
    proto: String(row.proto || 'tcp').toLowerCase(),
    direction: side.direction,
    bytesOut: side.inbound ? Number(row.resp_bytes) || 0 : Number(row.orig_bytes) || 0,
    bytesIn: side.inbound ? Number(row.orig_bytes) || 0 : Number(row.resp_bytes) || 0,
    pktsOut: side.inbound ? Number(row.resp_pkts) || 0 : Number(row.orig_pkts) || 0,
    pktsIn: side.inbound ? Number(row.orig_pkts) || 0 : Number(row.resp_pkts) || 0,
    durationMs: Math.round((Number(row.duration) || 0) * 1000),
  };
  const outcome = tcpOutcome(row.proto, row.conn_state);
  if (outcome) event.tcpOutcome = outcome;
  return stamp(event, row);
}

/**
 * @param {any} row
 * @param {any} id
 * @param {number} ts
 * @param {(ip: string) => string} deviceFor
 */
function dns(row, id, ts, deviceFor) {
  if (!row.query) return null;
  return stamp(
    {
      type: 'dns',
      device: deviceFor(String(id.orig_h || '0.0.0.0')),
      ts,
      qname: String(row.query),
      qtype: String(row.qtype_name || 'A'),
      rcode: String(row.rcode_name || 'NOERROR'),
      resolver: String(id.resp_h || 'gateway'),
      answers: dnsAnswers(row),
    },
    row,
  );
}

/**
 * @param {any} row
 * @param {any} id
 * @param {number} ts
 * @param {(ip: string) => string} deviceFor
 */
function tls(row, id, ts, deviceFor) {
  if (!id.resp_h) return null;
  /** @type {Record<string, any>} */
  const event = {
    type: 'tls',
    device: deviceFor(String(id.orig_h || id.resp_h)),
    ts,
    dstIp: String(id.resp_h),
    dstPort: Number(id.resp_p) || 443,
  };
  if (row.server_name) event.sni = String(row.server_name);
  if (row.ja4) event.ja4 = String(row.ja4);
  if (row.version) event.version = String(row.version);
  const alpn = alpnList(row.next_protocol);
  if (alpn) event.alpn = alpn;
  if (row.issuer) event.cert = { issuer: String(row.issuer) };
  return stamp(event, row);
}

/**
 * @param {any} row
 * @param {any} id
 * @param {number} ts
 * @param {(ip: string) => string} deviceFor
 */
function http(row, id, ts, deviceFor) {
  if (!id.resp_h || !row.method) return null;
  const orig = String(id.orig_h || '');
  const resp = String(id.resp_h);
  const side = localSide(orig, resp);
  /** @type {Record<string, any>} */
  const event = {
    type: 'http',
    device: deviceFor(side.deviceIp),
    ts,
    dstIp: resp,
    dstPort: Number(id.resp_p) || 80,
    method: String(row.method),
  };
  if (side.direction) event.direction = side.direction;
  if (row.host) event.host = String(row.host);
  if (row.uri) event.path = String(row.uri);
  return event;
}

/**
 * `out` when the local address is the requester, `in` when it is the responder.
 * @param {string} src
 * @param {string} dst
 * @returns {{ deviceIp: string, direction?: 'out' | 'in' }}
 */
function localSide(src, dst) {
  if (src && isLocalAddress(src)) return { deviceIp: src, direction: 'out' };
  if (dst && isLocalAddress(dst)) return { deviceIp: dst, direction: 'in' };
  return { deviceIp: src || dst };
}

/**
 * Private, loopback, link-local, and IPv6 ULA addresses.
 * @param {string} ip
 * @returns {boolean}
 */
function isLocalAddress(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  let lower = ip.toLowerCase();
  if (lower.startsWith('[') && lower.endsWith(']')) lower = lower.slice(1, -1);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(lower);
  if (mapped) lower = mapped[1];
  if (
    lower.startsWith('10.') ||
    lower.startsWith('192.168.') ||
    lower.startsWith('127.') ||
    lower.startsWith('169.254.')
  ) {
    return true;
  }
  const part = /^172\.(\d+)\./.exec(lower);
  if (part) {
    const octet = Number(part[1]);
    if (octet >= 16 && octet <= 31) return true;
  }
  if (lower === '::' || lower === '::1') return true;
  if (/^fe[89ab][0-9a-f]/i.test(lower)) return true;
  return lower.startsWith('fc') || lower.startsWith('fd');
}

/**
 * @param {unknown} value
 * @returns {string[] | null}
 */
function alpnList(value) {
  if (typeof value === 'string' && value.length > 0 && value.length <= 32) return [value];
  return null;
}

/**
 * @param {string} log
 * @param {any} row
 * @param {any} id
 * @param {number} ts
 * @param {(ip: string) => string} deviceFor
 */
function application(log, row, id, ts, deviceFor) {
  const peer = id.orig_h ? String(id.orig_h) : '';
  const controller = id.resp_h ? String(id.resp_h) : peer;
  if (!peer) return null;
  const mapped = appOp(log, row);
  if (!mapped) return null;
  /** @type {Record<string, any>} */
  const event = {
    type: 'app',
    device: deviceFor(controller),
    ts,
    proto: mapped.proto,
    role: 'server',
    peerIp: peer,
    op: mapped.op,
  };
  if (mapped.target) event.target = mapped.target;
  if (mapped.unitId != null) event.unitId = mapped.unitId;
  if (mapped.flags) event.flags = mapped.flags;
  return stamp(event, row);
}

/**
 * @param {string} log
 * @param {any} row
 */
function appOp(log, row) {
  const extra = appExtras(log, row);
  if (log === 'modbus') {
    return { proto: 'modbus', op: String(row.func || 'read'), target: text(row.address), ...extra };
  }
  if (log === 'dnp3')
    return { proto: 'dnp3', op: String(row.fc_request || row.function || 'read') };
  if (log === 'bacnet')
    return { proto: 'bacnet', op: String(row.service || row.pdu_service || 'read') };
  if (log === 's7comm') return { proto: 's7', op: String(row.function || row.rosctr || 'read') };
  if (log === 'enip') return { proto: 'enip', op: String(row.command || 'read') };
  if (log === 'mqtt_connect') return { proto: 'mqtt', op: 'CONNECT', ...extra };
  if (log === 'mqtt_subscribe') {
    return { proto: 'mqtt', op: 'SUBSCRIBE', target: text(row.topic || first(row.topics)) };
  }
  if (log === 'mqtt_publish') {
    return { proto: 'mqtt', op: 'PUBLISH', target: text(row.topic), ...extra };
  }
  return null;
}

/**
 * @param {unknown} value
 */
function text(value) {
  if (value == null || value === '') return undefined;
  return String(value).slice(0, 255);
}

/**
 * @param {unknown} value
 */
function first(value) {
  return Array.isArray(value) ? value[0] : undefined;
}

module.exports = { createParser };
