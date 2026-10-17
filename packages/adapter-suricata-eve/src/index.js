'use strict';

/**
 * Parse one Suricata EVE JSON line.
 * `flow`, `dns`, `tls`, and `http` become iotwarden events.
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
  return {
    type: 'flow',
    device: deviceFor(src),
    ts,
    srcIp: src,
    srcPort: Number(row.src_port) || 0,
    dstIp: dst,
    dstPort: Number(row.dest_port) || 0,
    proto: String(row.proto || 'TCP').toLowerCase(),
    direction: 'out',
    bytesOut: Number(stats.bytes_toserver) || 0,
    bytesIn: Number(stats.bytes_toclient) || 0,
    pktsOut: Number(stats.pkts_toserver) || 0,
    pktsIn: Number(stats.pkts_toclient) || 0,
    durationMs: 0,
  };
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
        answers.push({ type: String(item.rrtype || 'A'), value: String(item.rdata), ttl: 0 });
    }
  }
  return {
    type: 'dns',
    device: deviceFor(src || '0.0.0.0'),
    ts,
    qname: String(qname),
    qtype: String(record.type || 'A'),
    rcode: String(record.rcode || 'NOERROR'),
    resolver: dst || 'gateway',
    answers,
  };
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
  return event;
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
  /** @type {Record<string, any>} */
  const event = {
    type: 'http',
    device: deviceFor(src || dst),
    ts,
    dstIp: dst,
    dstPort: Number(row.dest_port) || 80,
    method: String(record.http_method),
  };
  if (record.hostname) event.host = String(record.hostname);
  if (record.url) event.path = String(record.url);
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

module.exports = { createParser };
