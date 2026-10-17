'use strict';

const FLOW =
  /(tcp|udp|icmp|gre)\s+\d+\s+\d+\s+\S+\s+src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)(?:\s+packets=(\d+))?(?:\s+bytes=(\d+))?/i;

/**
 * Stream parser for `conntrack -L` and `conntrack -E` lines.
 * The first src/dst pair is the original direction.
 * @param {{ device?: (srcIp: string) => string, direction?: (srcIp: string, dstIp: string) => 'out'|'in'|'lan', now?: () => number }} [opts]
 */
function createParser(opts = {}) {
  const device = opts.device || ((ip) => ip);
  const direction = opts.direction || (() => 'out');
  const now = opts.now || (() => 0);
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      const match = FLOW.exec(line);
      if (!match) return [];
      const proto = match[1].toLowerCase();
      const srcIp = match[2];
      const dstIp = match[3];
      const srcPort = Number(match[4]);
      const dstPort = Number(match[5]);
      const packets = match[6] ? Number(match[6]) : 1;
      const bytes = match[7] ? Number(match[7]) : 0;
      return [
        {
          type: 'flow',
          device: device(srcIp),
          ts: now(),
          srcIp,
          srcPort,
          dstIp,
          dstPort,
          proto,
          direction: direction(srcIp, dstIp),
          bytesOut: bytes,
          bytesIn: 0,
          pktsOut: packets,
          pktsIn: 0,
          durationMs: 0,
        },
      ];
    },
  };
}

module.exports = { createParser };
