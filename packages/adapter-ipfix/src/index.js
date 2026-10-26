'use strict';

// UNVERIFIED: template layout follows RFC 7011 field ids, not a live exporter.

/**
 * Parse one IPFIX (v10) or NetFlow v9 buffer into flow events.
 * Template cache is capped at 256.
 * @param {{ device?: (ip: string) => string }} [opts]
 */
function createParser(opts = {}) {
  const deviceFor = opts.device || ((ip) => ip);
  /** @type {Map<number, { fields: { id: number, len: number }[] }>} */
  const templates = new Map();
  return {
    /**
     * @param {Buffer} buffer
     * @returns {object[]}
     */
    write(buffer) {
      if (!Buffer.isBuffer(buffer) || buffer.length < 16) return [];
      const version = buffer.readUInt16BE(0);
      if (version !== 9 && version !== 10) return [];
      let offset = version === 9 ? 20 : 16;
      /** @type {object[]} */
      const events = [];
      while (offset + 4 <= buffer.length) {
        const setId = buffer.readUInt16BE(offset);
        const length = buffer.readUInt16BE(offset + 2);
        if (length < 4 || offset + length > buffer.length) break;
        const body = buffer.subarray(offset + 4, offset + length);
        if (setId === 0 || setId === 2) readTemplates(templates, body);
        else if (setId >= 256 && templates.has(setId)) {
          events.push(...readData(templates.get(setId), body, deviceFor));
        }
        offset += length;
      }
      return events;
    },
  };
}

/**
 * @param {Map<number, { fields: { id: number, len: number }[] }>} templates
 * @param {Buffer} body
 */
function readTemplates(templates, body) {
  let offset = 0;
  while (offset + 4 <= body.length) {
    const id = body.readUInt16BE(offset);
    const count = body.readUInt16BE(offset + 2);
    offset += 4;
    /** @type {{ id: number, len: number }[]} */
    const fields = [];
    for (let i = 0; i < count && offset + 4 <= body.length; i += 1) {
      fields.push({ id: body.readUInt16BE(offset), len: body.readUInt16BE(offset + 2) });
      offset += 4;
    }
    if (templates.size >= 256) {
      const oldest = templates.keys().next().value;
      if (oldest != null) templates.delete(oldest);
    }
    templates.set(id, { fields });
  }
}

/**
 * @param {{ fields: { id: number, len: number }[] } | undefined} template
 * @param {Buffer} body
 * @param {(ip: string) => string} deviceFor
 */
function readData(template, body, deviceFor) {
  if (!template) return [];
  const width = template.fields.reduce((sum, field) => sum + field.len, 0);
  if (width <= 0) return [];
  /** @type {object[]} */
  const events = [];
  for (let offset = 0; offset + width <= body.length; offset += width) {
    /** @type {Record<string, any>} */
    const row = {};
    let cursor = offset;
    for (const field of template.fields) {
      const slice = body.subarray(cursor, cursor + field.len);
      cursor += field.len;
      if (field.id === 8 || field.id === 12) row[field.id === 8 ? 'src' : 'dst'] = ipv4(slice);
      else if (field.id === 7) row.srcPort = u16(slice);
      else if (field.id === 11) row.dstPort = u16(slice);
      else if (field.id === 4) row.proto = protoOf(slice);
      else if (field.id === 1) row.bytes = u32(slice);
      else if (field.id === 2) row.packets = u32(slice);
    }
    if (!row.src || !row.dst) continue;
    events.push({
      type: 'flow',
      device: deviceFor(row.src),
      ts: 0,
      srcIp: row.src,
      dstIp: row.dst,
      srcPort: row.srcPort || 0,
      dstPort: row.dstPort || 0,
      proto: row.proto == null ? 'tcp' : row.proto,
      bytesOut: row.bytes || 0,
      bytesIn: 0,
      pktsOut: row.packets || 0,
      pktsIn: 0,
      durationMs: 0,
      direction: 'out',
    });
  }
  return events;
}

/**
 * @param {Buffer} slice
 */
function ipv4(slice) {
  if (slice.length < 4) return '';
  return `${slice[0]}.${slice[1]}.${slice[2]}.${slice[3]}`;
}

/**
 * @param {Buffer} slice
 * @returns {number}
 */
function u16(slice) {
  return slice.length >= 2 ? slice.readUInt16BE(0) : 0;
}

/**
 * @param {Buffer} slice
 * @returns {number}
 */
function u32(slice) {
  return slice.length >= 4 ? slice.readUInt32BE(0) : 0;
}

/**
 * ICMP, TCP, UDP, GRE, and ESP keep their names. Any other protocol stays a number.
 * A short field is omitted.
 * @param {Buffer} slice
 * @returns {'icmp' | 'tcp' | 'udp' | 'gre' | 'esp' | number | undefined}
 */
function protoOf(slice) {
  if (slice.length < 1) return undefined;
  const n = slice[0];
  if (n === 1) return 'icmp';
  if (n === 6) return 'tcp';
  if (n === 17) return 'udp';
  if (n === 47) return 'gre';
  if (n === 50) return 'esp';
  return n;
}

module.exports = { createParser };
