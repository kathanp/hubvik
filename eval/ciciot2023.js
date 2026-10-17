'use strict';

/**
 * UNVERIFIED: written from documentation, not run on real data.
 *
 * CICIoT2023 publishes PCAPs grouped by attack category. This joiner does not
 * read those PCAPs. It reads Zeek `conn.log`, `dns.log`, and `ssl.log` that a
 * human produced from one PCAP and placed in a directory named with that
 * PCAP's attack category. A directory named `Benign` is benign. Any other
 * directory name is the malicious detailed label.
 */

const fs = require('node:fs');
const path = require('node:path');
const { createParser } = require('../packages/adapter-zeek/src/index.js');
const { readZeekTsv, deviceOf } = require('./zeek-tsv.js');

const LOGS = [
  ['conn.log', 'conn'],
  ['dns.log', 'dns'],
  ['ssl.log', 'ssl'],
];

/**
 * @param {string} dir
 * @returns {any[]}
 */
function loadCiciot2023(dir) {
  const categories = fs
    .readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  if (categories.length === 0) throw new Error(`no category directories in ${dir}`);
  /** @type {any[]} */
  const rows = [];
  for (const category of categories) {
    const benign = category.toLowerCase() === 'benign';
    for (const [name, log] of LOGS) {
      const file = path.join(dir, category, name);
      if (!fs.existsSync(file)) continue;
      rows.push(...readLog(file, log, category, benign));
    }
  }
  if (rows.length === 0) throw new Error(`no Zeek rows in ${dir}`);
  return rows;
}

/**
 * @param {string} file
 * @param {string} log
 * @param {string} category
 * @param {boolean} benign
 * @returns {any[]}
 */
function readLog(file, log, category, benign) {
  const parsed = readZeekTsv(file);
  const parser = createParser({ log });
  /** @type {any[]} */
  const rows = [];
  for (const raw of parsed.rows) {
    const built = toRow(raw, parser, category, benign);
    if (built) rows.push(built);
  }
  return rows;
}

/**
 * @param {Record<string, string>} raw
 * @param {{ write: (line: string) => object[] }} parser
 * @param {string} category
 * @param {boolean} benign
 * @returns {any | null}
 */
function toRow(raw, parser, category, benign) {
  /** @type {Record<string, any>} */
  const row = {};
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
  if (raw['id.orig_h'] || raw['id.resp_h']) event.device = deviceOf(raw);
  return {
    device: event.device,
    ts: event.ts,
    malicious: !benign,
    label: benign ? 'Benign' : 'Malicious',
    detailedLabel: benign ? '-' : category,
    event,
  };
}

module.exports = { loadCiciot2023 };
