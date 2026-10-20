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
          proto: counter.protocol === 'udp' ? 'udp' : 'tcp',
          bytesOut: Number(counter.bytes) || 0,
          pktsOut: Number(counter.packets) || 0,
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

module.exports = { createParser };
