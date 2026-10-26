'use strict';

// UNVERIFIED: accepts nft JSON counter objects and a small monitor subset.

/**
 * Parse nftables JSON into flow summaries.
 * @param {{ device?: (ip: string) => string, now?: () => number }} [opts]
 */
function createParser(opts = {}) {
  const deviceFor = opts.device || ((ip) => ip);
  const now = opts.now || (() => 0);
  return {
    /**
     * @param {string | object} raw
     * @returns {object[]}
     */
    write(raw) {
      let row = raw;
      if (typeof raw === 'string') {
        try {
          row = JSON.parse(raw);
        } catch {
          return [];
        }
      }
      if (!row || typeof row !== 'object') return [];
      const counter = row.counter || (row.nftables && counterOf(row.nftables));
      if (!counter || !counter.saddr || !counter.daddr) return [];
      return [
        {
          type: 'flow',
          device: deviceFor(String(counter.saddr)),
          ts: now(),
          srcIp: String(counter.saddr),
          dstIp: String(counter.daddr),
          srcPort: Number(counter.sport) || 0,
          dstPort: Number(counter.dport) || 0,
          proto: protoName(counter.protocol),
          bytesOut: Number(counter.bytes) || 0,
          bytesIn: 0,
          pktsOut: Number(counter.packets) || 0,
          pktsIn: 0,
          durationMs: 0,
          direction: 'out',
        },
      ];
    },
  };
}

/**
 * @param {any[]} list
 */
function counterOf(list) {
  for (const item of list) {
    if (item && item.counter) return item.counter;
  }
  return null;
}

/**
 * Known names stay names. A numeric protocol stays a number. Anything else is TCP.
 * @param {unknown} value
 * @returns {string | number}
 */
function protoName(value) {
  const name = String(value || '').toLowerCase();
  if (name === 'tcp' || name === 'udp' || name === 'icmp' || name === 'gre' || name === 'esp') {
    return name;
  }
  const n = Number(name);
  if (name !== '' && Number.isInteger(n) && n >= 0 && n <= 255) return n;
  return 'tcp';
}

module.exports = { createParser };
