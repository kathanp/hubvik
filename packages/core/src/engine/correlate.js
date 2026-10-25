'use strict';

const { HubvikError } = require('../errors');

const { FORBIDDEN_KEYS } = require('./constants');

const CAP = 4096;
const TTL_MS = 120000;
const UID_MAX = 64;
const NAME_MAX = 255;

/**
 * Engine-wide table of sensor ids to a destination name.
 * Names come from DNS and TLS. A later flow with the same id receives the name.
 * @returns {Map<string, { ts: number, name: string, fromDns: boolean }>}
 */
function createTable() {
  return new Map();
}

/**
 * Remember a name, or copy a stored name onto a flow that does not have one.
 * @param {Map<string, { ts: number, name: string, fromDns: boolean }>} table
 * @param {any} event
 * @returns {void}
 */
function note(table, event) {
  if (!event || typeof event.uid !== 'string') return;
  if (event.type === 'flow') fillFlow(table, event);
  else if (event.type === 'dns' || event.type === 'tls') storeName(table, event);
}

/**
 * @param {Map<string, { ts: number, name: string, fromDns: boolean }>} table
 * @returns {unknown[][]}
 */
function toJSON(table) {
  /** @type {unknown[][]} */
  const rows = [];
  for (const [uid, row] of table) rows.push([uid, row.ts, row.name, row.fromDns]);
  return rows;
}

/**
 * @param {unknown} raw
 * @returns {Map<string, { ts: number, name: string, fromDns: boolean }>}
 */
function fromJSON(raw) {
  if (!Array.isArray(raw) || raw.length > CAP) invalid();
  const table = createTable();
  for (const item of raw) table.set(readUid(item), readRow(item));
  return table;
}

/**
 * @param {Map<string, { ts: number, name: string, fromDns: boolean }>} table
 * @param {any} event
 * @returns {void}
 */
function fillFlow(table, event) {
  const row = table.get(event.uid);
  if (!row) return;
  if (event.ts - row.ts > TTL_MS) {
    table.delete(event.uid);
    return;
  }
  if (event.dstName) return;
  event.dstName = row.name;
  if (event.dst === event.dstIp) event.dst = row.name;
}

/**
 * DNS replaces a TLS name. A second DNS name does not replace the first.
 * @param {Map<string, { ts: number, name: string, fromDns: boolean }>} table
 * @param {any} event
 * @returns {void}
 */
function storeName(table, event) {
  const incoming = event.type === 'dns' ? event.qname : event.sni;
  if (typeof incoming !== 'string' || incoming.length === 0) return;
  const fromDns = event.type === 'dns';
  const row = table.get(event.uid);
  if (row && event.ts - row.ts <= TTL_MS) {
    row.ts = event.ts;
    if (fromDns && !row.fromDns) {
      row.name = incoming;
      row.fromDns = true;
    }
    return;
  }
  if (row) table.delete(event.uid);
  evict(table);
  table.set(event.uid, { ts: event.ts, name: incoming, fromDns });
}

/**
 * @param {Map<string, { ts: number, name: string, fromDns: boolean }>} table
 * @returns {void}
 */
function evict(table) {
  while (table.size >= CAP) {
    const oldest = table.keys().next().value;
    if (oldest === undefined) return;
    table.delete(oldest);
  }
}

/**
 * @param {unknown} item
 * @returns {string}
 */
function readUid(item) {
  if (!Array.isArray(item) || item.length !== 4) invalid();
  const uid = item[0];
  if (typeof uid !== 'string' || uid.length === 0 || uid.length > UID_MAX) invalid();
  if (FORBIDDEN_KEYS.has(uid)) invalid();
  return uid;
}

/**
 * @param {unknown} item
 * @returns {{ ts: number, name: string, fromDns: boolean }}
 */
function readRow(item) {
  const row = /** @type {unknown[]} */ (item);
  const ts = row[1];
  const name = row[2];
  const fromDns = row[3];
  if (typeof ts !== 'number' || !Number.isInteger(ts)) invalid();
  if (typeof name !== 'string' || name.length === 0 || name.length > NAME_MAX) invalid();
  if (typeof fromDns !== 'boolean') invalid();
  return { ts, name, fromDns };
}

/**
 * @returns {never}
 */
function invalid() {
  throw new HubvikError('CHECKPOINT_CORRELATE_IS_INVALID', 'checkpoint correlate is invalid');
}

module.exports = { createTable, note, toJSON, fromJSON };
