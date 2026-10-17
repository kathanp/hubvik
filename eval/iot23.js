'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createParser } = require('../packages/adapter-zeek/src/index.js');

/**
 * Read IoT-23 labeled Zeek conn.log files. TSV, with `label` and `detailed-label`.
 * Each data row is handed to adapter-zeek as one JSON conn object. Tier selection
 * is the caller's; this joiner only emits flow events.
 * @param {string} dir
 * @returns {any[]}
 */
function loadIot23(dir) {
  const files = connFiles(dir);
  if (files.length === 0) throw new Error(`no conn.log files in ${dir}`);
  /** @type {any[]} */
  const rows = [];
  for (const file of files) rows.push(...readConn(file));
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
  const parser = createParser({ log: 'conn' });
  const text = fs.readFileSync(file, 'utf8');
  /** @type {string[]} */
  let fields = [];
  let separator = '\t';
  let empty = '(empty)';
  let unset = '-';
  /** @type {any[]} */
  const rows = [];
  for (const line of text.split(/\r?\n/)) {
    if (line.length === 0) continue;
    if (line.startsWith('#')) {
      if (line.startsWith('#separator '))
        separator = decodeSeparator(line.slice('#separator '.length));
      else if (line.startsWith('#empty_field ')) empty = line.slice('#empty_field '.length).trim();
      else if (line.startsWith('#unset_field ')) unset = line.slice('#unset_field '.length).trim();
      else if (line.startsWith('#fields')) {
        fields = line.split(separator).slice(1);
        if (!fields.includes('label') || !fields.includes('detailed-label')) {
          throw new Error(`${file} is missing label or detailed-label`);
        }
      }
      continue;
    }
    if (fields.length === 0) throw new Error(`${file} has no #fields header`);
    const values = line.split(separator);
    if (values.length !== fields.length) {
      throw new Error(`${file} has a row with ${values.length} fields, expected ${fields.length}`);
    }
    const built = toRow(fields, values, empty, unset, parser);
    if (built) rows.push(built);
  }
  return rows;
}

/**
 * @param {string} raw
 * @returns {string}
 */
function decodeSeparator(raw) {
  const text = raw.trim();
  if (text === '\\x09') return '\t';
  return text;
}

/**
 * @param {string[]} fields
 * @param {string[]} values
 * @param {string} empty
 * @param {string} unset
 * @param {{ write: (line: string) => object[] }} parser
 * @returns {any | null}
 */
function toRow(fields, values, empty, unset, parser) {
  /** @type {Record<string, any>} */
  const row = {};
  let label = '';
  let detailedLabel = '';
  for (let i = 0; i < fields.length; i += 1) {
    const name = fields[i];
    const value = values[i];
    if (value === empty || value === unset) continue;
    if (name === 'label') label = value;
    else if (name === 'detailed-label') detailedLabel = value;
    else if (name.startsWith('id.')) {
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
