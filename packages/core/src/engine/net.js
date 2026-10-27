'use strict';

const SUFFIXES = new Set(require('../data/suffixes.json'));

/**
 * @param {string} ip
 * @returns {number | null}
 */
function ipv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = (value * 256 + octet) >>> 0;
  }
  return value;
}

/**
 * @param {number} ip
 * @param {number} base
 * @param {number} bits
 * @returns {boolean}
 */
function inBlock(ip, base, bits) {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ip & mask) === (base & mask);
}

const V4_BOGONS = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
].map(([cidr, bits]) => ({ base: ipv4(String(cidr)), bits: Number(bits) }));

/**
 * Reserved, private, documentation, multicast, or otherwise not a global address.
 * @param {string} ip
 * @returns {boolean}
 */
/**
 * Lowercase, strip brackets, and unwrap `::ffff:a.b.c.d` to IPv4.
 * @param {string} ip
 * @returns {string}
 */
function unwrapMapped(ip) {
  let s = ip.toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped && ipv4(mapped[1]) != null) return mapped[1];
  return s;
}

/**
 * Reserved, private, documentation, multicast, or otherwise not a global address.
 * IPv4-mapped IPv6 is classified as the IPv4 host. Link-local is `fe80::/10`.
 * @param {string} ip
 * @returns {boolean}
 */
function isBogon(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  const lower = unwrapMapped(ip);
  const v4 = ipv4(lower);
  if (v4 != null) return V4_BOGONS.some((block) => inBlock(v4, block.base ?? 0, block.bits));
  if (!lower.includes(':')) return false;
  if (lower === '::' || lower === '::1') return true;
  if (/^fe[89ab][0-9a-f]/i.test(lower)) return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('ff') || lower.startsWith('2001:db8:')) return true;
  return false;
}

/**
 * @param {string} ip
 * @returns {boolean}
 */
function isPublic(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  if (ipv4(ip) == null && !ip.includes(':')) return false;
  return !isBogon(ip);
}

/**
 * @param {string} name
 * @returns {boolean}
 */
function isIpName(name) {
  return ipv4(name) != null || name.includes(':');
}

/**
 * Registered domain (eTLD+1). IP addresses have no family.
 * Single-label TLDs use the last two labels. Multi-label suffixes come from the bundled snapshot.
 * @param {string | undefined} name
 * @returns {string | null}
 */
function domainFamily(name) {
  if (!name || isIpName(name)) return null;
  // Scan targets such as 203.0.113.4-12 are not registrable names.
  if (/^\d{1,3}(\.\d{1,3}){3}/.test(name)) return null;
  const labels = name.toLowerCase().split('.').filter(Boolean);
  if (labels.length < 2) return null;
  const limit = Math.min(3, labels.length - 1);
  for (let size = limit; size >= 2; size--) {
    const suffix = labels.slice(-size).join('.');
    if (!SUFFIXES.has(suffix)) continue;
    const start = labels.length - size - 1;
    if (start < 0) return labels.join('.');
    return labels.slice(start).join('.');
  }
  return labels.slice(-2).join('.');
}

/**
 * IPv4 224.0.0.0/4 or IPv6 ff00::/8.
 * @param {string} ip
 * @returns {boolean}
 */
function isMulticast(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  const lower = unwrapMapped(ip);
  const v4 = ipv4(lower);
  if (v4 != null) return inBlock(v4, ipv4('224.0.0.0') ?? 0, 4);
  return lower.startsWith('ff');
}

/**
 * IPv4 limited broadcast.
 * @param {string} ip
 * @returns {boolean}
 */
function isBroadcast(ip) {
  return ip === '255.255.255.255';
}

/**
 * IPv4 169.254.0.0/16 or IPv6 fe80::/10.
 * @param {string} ip
 * @returns {boolean}
 */
function isLinkLocal(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  const lower = unwrapMapped(ip);
  const v4 = ipv4(lower);
  if (v4 != null) return inBlock(v4, ipv4('169.254.0.0') ?? 0, 16);
  return /^fe[89ab][0-9a-f]/i.test(lower);
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isPrivateAnswer(value) {
  if (typeof value !== 'string') return false;
  const ip = value.toLowerCase();
  if (ip === '0.0.0.0' || ip === '::' || ip === '::1') return true;
  return isBogon(ip);
}

/**
 * RFC1918, link-local, or ULA. Not documentation, CGNAT, loopback, or multicast.
 * @param {string} ip
 * @returns {boolean}
 */
function isLanUnicast(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  const lower = unwrapMapped(ip);
  const v4 = ipv4(lower);
  if (v4 != null) {
    return (
      inBlock(v4, ipv4('10.0.0.0') ?? 0, 8) ||
      inBlock(v4, ipv4('172.16.0.0') ?? 0, 12) ||
      inBlock(v4, ipv4('192.168.0.0') ?? 0, 16) ||
      inBlock(v4, ipv4('169.254.0.0') ?? 0, 16)
    );
  }
  if (!lower.includes(':')) return false;
  if (/^fe[89ab][0-9a-f]/i.test(lower)) return true;
  return lower.startsWith('fc') || lower.startsWith('fd');
}

module.exports = {
  ipv4,
  inBlock,
  isBogon,
  isPublic,
  isIpName,
  domainFamily,
  isMulticast,
  isBroadcast,
  isLinkLocal,
  isPrivateAnswer,
  isLanUnicast,
};
