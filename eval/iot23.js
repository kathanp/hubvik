'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createParser } = require('../packages/adapter-zeek/src/index.js');
const { readZeekTsv, deviceOf } = require('./zeek-tsv.js');

/**
 * Read IoT-23 labeled Zeek conn.log files. TSV, with `label` and `detailed-label`.
 * Each data row is handed to adapter-zeek as one JSON conn object. The engine tier
 * is the caller's; this joiner only emits flow events.
 * Device is `id.orig_h` for outbound and `id.resp_h` for inbound, per row in the capture.
 * @param {string} dir
 * @returns {any[]}
 */
function loadIot23(dir) {
  const files = connFiles(dir);
  if (files.length === 0) throw new Error(`no conn.log files in ${dir}`);
  /** @type {any[]} */
  const rows = [];
  for (const file of files) {
    for (const row of readConn(file)) rows.push(row);
  }
  if (rows.length === 0) throw new Error(`no conn rows in ${dir}`);
  return rows;
}

/**
 * @param {string} dir
 * @returns {string[]}
 */
function connFiles(dir) {
  const stat = fs.statSync(dir);
  if (stat.isFile()) return [dir];
  /** @type {string[]} */
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...connFiles(full));
    else if (entry.isFile() && isConnName(entry.name)) out.push(full);
  }
  return out.sort();
}

/**
 * @param {string} name
 * @returns {boolean}
 */
function isConnName(name) {
  return name === 'conn.log' || name.startsWith('conn.log.');
}

/**
 * @param {string} file
 * @returns {any[]}
 */
function readConn(file) {
  const parsed = readZeekTsv(file, { requireLabels: true });
  const parser = createParser({ log: 'conn' });
  /** @type {any[]} */
  const rows = [];
  for (const raw of parsed.rows) {
    const built = toRow(raw, parser);
    if (built) rows.push(built);
  }
  return rows;
}

/**
 * @param {Record<string, string>} raw
 * @param {{ write: (line: string) => object[] }} parser
 * @returns {any | null}
 */
function toRow(raw, parser) {
  /** @type {Record<string, any>} */
  const row = {};
  const label = raw.label || '';
  const detailedLabel = raw['detailed-label'] || '';
  for (const [name, value] of Object.entries(raw)) {
    if (name === 'label' || name === 'detailed-label') continue;
    if (name.startsWith('id.')) {
      if (!row.id) row.id = {};
      row.id[name.slice(3)] = value;
    } else if (
      name === 'ts' ||
      name === 'duration' ||
      name.endsWith('_bytes') ||
      name.endsWith('_pkts')
    ) {
      row[name] = Number(value);
    } else row[name] = value;
  }
  const events = parser.write(JSON.stringify(row));
  if (events.length === 0) return null;
  const event = events[0];
  event.device = deviceOf(raw);
  const malicious = label.toLowerCase() !== 'benign';
  return {
    device: event.device,
    ts: event.ts,
    malicious,
    label,
    detailedLabel,
    event,
  };
}

module.exports = { loadIot23 };
