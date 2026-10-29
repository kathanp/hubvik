'use strict';

const { readFileSync } = require('node:fs');

const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
const PROTO = new Map([
  [6, 'tcp'],
  [17, 'udp'],
  [1, 'icmp'],
  ['tcp', 'tcp'],
  ['udp', 'udp'],
  ['icmp', 'icmp'],
]);

/**
 * Parse a MUD file (RFC 8520 JSON) into the `{ allows }` object `loadMud` accepts.
 * This function does not fetch the file and does not install an ACL.
 * @param {string} text
 * @returns {{ allows: { dstPort?: number, proto?: string, domain?: string, direction?: 'out' | 'in' }[] }}
 */
function parseMud(text) {
  if (typeof text !== 'string') throw new TypeError('mud file is invalid');
  let doc;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new TypeError('mud file is invalid');
  }
  assertSafe(doc, 'mud file is invalid');
  const mud = doc['ietf-mud:mud'];
  const acls = doc['ietf-access-control-list:acls'];
  if (!mud || typeof mud !== 'object' || !acls || typeof acls !== 'object') {
    throw new TypeError('mud file is invalid');
  }
  assertSafe(mud, 'mud file is invalid');
  assertSafe(acls, 'mud file is invalid');
  if (!Array.isArray(acls.acl)) throw new TypeError('mud file is invalid');
  /** @type {Map<string, 'out' | 'in'>} */
  const directionByName = new Map();
  collectNames(mud['from-device-policy'], 'out', directionByName);
  collectNames(mud['to-device-policy'], 'in', directionByName);
  /** @type {{ dstPort?: number, proto?: string, domain?: string, direction?: 'out' | 'in' }[]} */
  const allows = [];
  for (const acl of acls.acl) {
    assertSafe(acl, 'mud acl is invalid');
    const direction = typeof acl.name === 'string' ? directionByName.get(acl.name) : undefined;
    const aces = acl.aces && Array.isArray(acl.aces.ace) ? acl.aces.ace : [];
    for (const ace of aces) {
      assertSafe(ace, 'mud ace is invalid');
      const forwarding = ace.actions && ace.actions.forwarding;
      if (forwarding !== 'accept') continue;
      const allow = allowFrom(ace.matches, direction);
      if (allow) allows.push(allow);
    }
  }
  if (allows.length > 64) throw new TypeError('mud allows exceed 64');
  return { allows };
}

/**
 * Read a MUD file the host already fetched. No network call.
 * @param {string} file
 */
function loadMudFile(file) {
  if (typeof file !== 'string' || file.length === 0) throw new TypeError('mud file is invalid');
  return parseMud(readFileSync(file, 'utf8'));
}

/**
 * @param {any} policy
 * @param {'out' | 'in'} direction
 * @param {Map<string, 'out' | 'in'>} map
 */
function collectNames(policy, direction, map) {
  if (policy == null) return;
  assertSafe(policy, 'mud policy is invalid');
  const lists = policy['access-lists'];
  if (lists == null) return;
  assertSafe(lists, 'mud policy is invalid');
  const names = lists['access-list'];
  if (!Array.isArray(names)) return;
  for (const item of names) {
    assertSafe(item, 'mud policy is invalid');
    if (typeof item.name === 'string') map.set(item.name, direction);
  }
}

/**
 * @param {any} matches
 * @param {'out' | 'in' | undefined} direction
 */
function allowFrom(matches, direction) {
  if (matches == null) return direction ? { direction } : null;
  assertSafe(matches, 'mud match is invalid');
  /** @type {{ dstPort?: number, proto?: string, domain?: string, direction?: 'out' | 'in' }} */
  const allow = {};
  if (direction) allow.direction = direction;
  const proto = protoOf(matches.ipv4) || protoOf(matches.ipv6);
  if (proto) allow.proto = proto;
  const port = portOf(matches.tcp) || portOf(matches.udp);
  if (port != null) allow.dstPort = port;
  const domain = domainOf(matches) || domainOf(matches.ipv4) || domainOf(matches.ipv6);
  if (domain) allow.domain = domain;
  if (!allow.proto && allow.dstPort == null && !allow.domain && !allow.direction) return null;
  return allow;
}

/**
 * @param {any} node
 * @returns {string | null}
 */
function protoOf(node) {
  if (!node || typeof node !== 'object') return null;
  assertSafe(node, 'mud match is invalid');
  if (node.protocol == null) return null;
  const name = PROTO.get(node.protocol);
  if (!name) throw new TypeError('mud proto is invalid');
  return name;
}

/**
 * @param {any} node
 * @returns {number | null}
 */
function portOf(node) {
  if (!node || typeof node !== 'object') return null;
  assertSafe(node, 'mud match is invalid');
  const dest = node['destination-port'];
  if (dest == null) return null;
  assertSafe(dest, 'mud dstPort is invalid');
  const port = dest.port != null ? dest.port : dest['lower-port'];
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new TypeError('mud dstPort is invalid');
  }
  return port;
}

/**
 * @param {any} node
 * @returns {string | null}
 */
function domainOf(node) {
  if (!node || typeof node !== 'object') return null;
  const name = node['ietf-acldns:dst-dnsname'];
  if (name == null) return null;
  if (typeof name !== 'string' || name.length === 0 || name.length > 255) {
    throw new TypeError('mud domain is invalid');
  }
  return name.toLowerCase();
}

/**
 * @param {any} value
 * @param {string} message
 */
function assertSafe(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(message);
  for (const key of Object.keys(value)) {
    if (FORBIDDEN.has(key)) throw new TypeError(message);
  }
}

module.exports = { parseMud, loadMudFile };
