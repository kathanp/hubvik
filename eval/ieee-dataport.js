'use strict';

/**
 * UNVERIFIED: written from documentation, not run on real data.
 *
 * The IEEE DataPort IoT network intrusion set publishes 42 PCAPs: benign
 * traffic, ARP spoofing, scans, SYN floods, and Mirai. This joiner does not
 * read those PCAPs. A human extracts each PCAP into a directory named with
 * that PCAP's category. A directory named `Benign` is benign. Any other
 * directory name is the malicious detailed label.
 *
 * `conn.log` is Zeek TSV. `arp.tsv` and `dhcp.tsv` are the host-side ARP and
 * DHCP extraction, also Zeek TSV. `arp.tsv` fields: ts, ip, mac, op, and an
 * optional device. `dhcp.tsv` fields: ts, mac, msg, and optional device,
 * server_ip, requested_ip.
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
function loadIeeeDataport(dir) {
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
    const base = path.join(dir, category);
    for (const [name, log] of LOGS) {
      const file = path.join(base, name);
      if (!fs.existsSync(file)) continue;
      rows.push(...readZeek(file, log, category, benign));
    }
    const arp = path.join(base, 'arp.tsv');
    if (fs.existsSync(arp)) rows.push(...readLink(arp, 'arp', category, benign));
    const dhcp = path.join(base, 'dhcp.tsv');
    if (fs.existsSync(dhcp)) rows.push(...readLink(dhcp, 'dhcp', category, benign));
  }
  if (rows.length === 0) throw new Error(`no extracted rows in ${dir}`);
  return rows;
}

/**
 * @param {string} file
 * @param {string} log
 * @param {string} category
 * @param {boolean} benign
 * @returns {any[]}
 */
function readZeek(file, log, category, benign) {
  const parsed = readZeekTsv(file);
  const parser = createParser({ log });
  /** @type {any[]} */
  const rows = [];
  for (const raw of parsed.rows) {
    const built = zeekRow(raw, parser, category, benign);
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
function zeekRow(raw, parser, category, benign) {
  /** @type {Record<string, any>} */
  const row = {};
  for (const [name, value] of Object.entries(raw)) {
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
  return labeled(event, event.device, category, benign);
}

/**
 * @param {string} file
 * @param {'arp' | 'dhcp'} kind
 * @param {string} category
 * @param {boolean} benign
 * @returns {any[]}
 */
function readLink(file, kind, category, benign) {
  const parsed = readZeekTsv(file);
  /** @type {any[]} */
  const rows = [];
  for (const raw of parsed.rows) {
    const built = linkRow(raw, kind, category, benign);
    if (built) rows.push(built);
  }
  return rows;
}

/**
 * @param {Record<string, string>} raw
 * @param {'arp' | 'dhcp'} kind
 * @param {string} category
 * @param {boolean} benign
 * @returns {any | null}
 */
function linkRow(raw, kind, category, benign) {
  const ts = Math.round(Number(raw.ts) * 1000);
  if (!Number.isFinite(ts)) return null;
  if (kind === 'arp') {
    if (!raw.ip || !raw.mac || !raw.op) return null;
    const event = {
      type: 'arp',
      device: raw.device || raw.ip,
      ts,
      ip: raw.ip,
      mac: raw.mac.toLowerCase(),
      op: raw.op,
    };
    return labeled(event, event.device, category, benign);
  }
  if (!raw.mac || !raw.msg) return null;
  /** @type {Record<string, any>} */
  const event = {
    type: 'dhcp',
    device: raw.device || raw.mac.toLowerCase(),
    ts,
    mac: raw.mac.toLowerCase(),
    msg: raw.msg,
  };
  if (raw.server_ip) event.serverIp = raw.server_ip;
  if (raw.requested_ip) event.requestedIp = raw.requested_ip;
  return labeled(event, event.device, category, benign);
}

/**
 * @param {any} event
 * @param {string} device
 * @param {string} category
 * @param {boolean} benign
 */
function labeled(event, device, category, benign) {
  return {
    device,
    ts: event.ts,
    malicious: !benign,
    label: benign ? 'Benign' : 'Malicious',
    detailedLabel: benign ? '-' : category,
    event,
  };
}

module.exports = { loadIeeeDataport };
