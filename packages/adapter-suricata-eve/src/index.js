'use strict';

/**
 * Parse one Suricata EVE JSON line.
 * `flow`, `dns`, `tls`, and `http` become hubvik events.
 * `alert` is passed through as `{ type: 'alert', ... }` for the host. Do not feed that object to the engine.
 * @param {{ device?: (ip: string) => string, now?: (iso: string) => number }} [opts]
 */
function createParser(opts = {}) {
  const deviceFor = opts.device || ((ip) => ip);
  const now = opts.now || ((iso) => Date.parse(iso) || 0);
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      if (typeof line !== 'string' || line.length === 0) return [];
      let row;
      try {
        row = JSON.parse(line);
      } catch {
        return [];
      }
      if (!row || typeof row !== 'object') return [];
      const event = build(row, deviceFor, now);
      return event ? [event] : [];
    },
  };
}

/**
 * @param {any} row
 * @param {(ip: string) => string} deviceFor
 * @param {(iso: string) => number} now
 */
function build(row, deviceFor, now) {
  const ts = now(typeof row.timestamp === 'string' ? row.timestamp : '');
  const src = String(row.src_ip || '');
  const dst = String(row.dest_ip || '');
  if (row.event_type === 'flow') return flow(row, ts, src, dst, deviceFor);
  if (row.event_type === 'dns') return dns(row, ts, src, dst, deviceFor);
  if (row.event_type === 'tls') return tls(row, ts, src, dst, deviceFor);
  if (row.event_type === 'http') return http(row, ts, src, dst, deviceFor);
  if (row.event_type === 'alert') return alert(row, ts, src, dst, deviceFor);
  return null;
}

/**
 * @param {any} row
 * @param {number} ts
 * @param {string} src
 * @param {string} dst
 * @param {(ip: string) => string} deviceFor
 */
function flow(row, ts, src, dst, deviceFor) {
  if (!src || !dst) return null;
  const stats = row.flow && typeof row.flow === 'object' ? row.flow : {};
  const side = flowSide(src, dst);
  /** @type {Record<string, any>} */
  const event = {
    type: 'flow',
    device: deviceFor(side.deviceIp),
    ts,
    srcIp: src,
    srcPort: Number(row.src_port) || 0,
    dstIp: dst,
    dstPort: Number(row.dest_port) || 0,
    proto: String(row.proto || 'TCP').toLowerCase(),
    direction: side.direction,
    bytesOut: side.inbound ? Number(stats.bytes_toclient) || 0 : Number(stats.bytes_toserver) || 0,
    bytesIn: side.inbound ? Number(stats.bytes_toserver) || 0 : Number(stats.bytes_toclient) || 0,
    pktsOut: side.inbound ? Number(stats.pkts_toclient) || 0 : Number(stats.pkts_toserver) || 0,
    pktsIn: side.inbound ? Number(stats.pkts_toserver) || 0 : Number(stats.pkts_toclient) || 0,
    durationMs: Math.round((Number(stats.age) || 0) * 1000),
  };
  const outcome = tcpOutcome(row, stats);
  if (outcome) event.tcpOutcome = outcome;
  return stamp(event, row);
}

/**
 * @param {any} row
 * @param {number} ts
 * @param {string} src
 * @param {string} dst
 * @param {(ip: string) => string} deviceFor
 */
function dns(row, ts, src, dst, deviceFor) {
  const record = row.dns && typeof row.dns === 'object' ? row.dns : {};
  const qname =
    record.rrname ||
    (Array.isArray(record.queries) && record.queries[0] && record.queries[0].rrname);
  if (!qname) return null;
  const answers = [];
  if (Array.isArray(record.answers)) {
    for (const item of record.answers) {
      if (item && item.rdata)
        answers.push({
          type: String(item.rrtype || 'A'),
          value: String(item.rdata),
          ttl: Number(item.ttl) || 0,
        });
    }
  }
  return stamp(
    {
      type: 'dns',
      device: deviceFor(src || '0.0.0.0'),
      ts,
      qname: String(qname),
      qtype: String(record.type || 'A'),
      rcode: String(record.rcode || 'NOERROR'),
      resolver: dst || 'gateway',
      answers,
    },
    row,
  );
}

/**
 * @param {any} row
 * @param {number} ts
 * @param {string} src
 * @param {string} dst
 * @param {(ip: string) => string} deviceFor
 */
function tls(row, ts, src, dst, deviceFor) {
  if (!dst) return null;
  const record = row.tls && typeof row.tls === 'object' ? row.tls : {};
  /** @type {Record<string, any>} */
  const event = {
    type: 'tls',
    device: deviceFor(src || dst),
    ts,
    dstIp: dst,
    dstPort: Number(row.dest_port) || 443,
  };
  if (record.sni) event.sni = String(record.sni);
  if (record.ja4) event.ja4 = String(record.ja4);
  if (record.version) event.version = String(record.version);
  const alpn = alpnList(record.alpn);
  if (alpn) event.alpn = alpn;
  return stamp(event, row);
}

/**
 * @param {any} row
 * @param {number} ts
 * @param {string} src
 * @param {string} dst
 * @param {(ip: string) => string} deviceFor
 */
function http(row, ts, src, dst, deviceFor) {
  const record = row.http && typeof row.http === 'object' ? row.http : {};
  if (!dst || !record.http_method) return null;
  const side = localSide(src, dst);
  /** @type {Record<string, any>} */
  const event = {
    type: 'http',
    device: deviceFor(side.deviceIp),
    ts,
    dstIp: dst,
    dstPort: Number(row.dest_port) || 80,
    method: String(record.http_method),
  };
  if (side.direction) event.direction = side.direction;
  if (record.hostname) event.host = String(record.hostname);
  if (record.url) event.path = String(record.url);
  return event;
}

/**
 * `out` when the local address is the source, `in` when it is the destination.
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
 * @param {any} row
 * @param {number} ts
 * @param {string} src
 * @param {string} dst
 * @param {(ip: string) => string} deviceFor
 */
/**
 * Public source to a local device is inbound. Both local is LAN. Otherwise outbound.
 * @param {string} src
 * @param {string} dst
 * @returns {{ deviceIp: string, direction: 'out' | 'in' | 'lan', inbound: boolean }}
 */
function flowSide(src, dst) {
  const srcLocal = isLocalAddress(src);
  const dstLocal = isLocalAddress(dst);
  if (srcLocal && dstLocal) return { deviceIp: src, direction: 'lan', inbound: false };
  if (dstLocal && !srcLocal) return { deviceIp: dst, direction: 'in', inbound: true };
  return { deviceIp: src || dst, direction: 'out', inbound: false };
}

/**
 * @param {any} row
 * @param {any} stats
 * @returns {'established' | 'reset' | 'no-response' | undefined}
 */
function tcpOutcome(row, stats) {
  if (String(row.proto || '').toLowerCase() !== 'tcp') return undefined;
  const tcp = row.tcp && typeof row.tcp === 'object' ? row.tcp : {};
  if (tcp.rst === true) return 'reset';
  const state = String(stats.state || '');
  if (state === 'established' || state === 'closed') return 'established';
  if (state === 'new' && (Number(stats.pkts_toclient) || 0) === 0) return 'no-response';
  return undefined;
}

/**
 * Suricata `flow_id` is the join key for `correlate`.
 * @param {Record<string, any>} event
 * @param {any} row
 * @returns {Record<string, any>}
 */
function stamp(event, row) {
  if (row.flow_id == null) return event;
  const uid = String(row.flow_id);
  if (uid.length > 0 && uid.length <= 64 && uid !== 'undefined') event.uid = uid;
  return event;
}

/**
 * @param {any} row
 * @param {number} ts
 * @param {string} src
 * @param {string} dst
 * @param {(ip: string) => string} deviceFor
 */
function alert(row, ts, src, dst, deviceFor) {
  const record = row.alert && typeof row.alert === 'object' ? row.alert : {};
  return {
    type: 'alert',
    device: deviceFor(src || dst || 'unknown'),
    ts,
    srcIp: src,
    dstIp: dst,
    signature: String(record.signature || ''),
    category: String(record.category || ''),
    severity: Number(record.severity) || 0,
  };
}

/**
 * Suricata records the negotiated protocol as one string.
 * @param {unknown} value
 * @returns {string[] | null}
 */
function alpnList(value) {
  if (typeof value === 'string' && value.length > 0 && value.length <= 32) return [value];
  return null;
}

module.exports = { createParser };
