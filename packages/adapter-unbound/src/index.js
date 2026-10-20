'use strict';

// UNVERIFIED: line shape is taken from Unbound's documented query/reply text.

const QUERY = /query:\s+(\S+)\s+(\S+)\s+(\S+)/;
const REPLY = /reply:\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?/;

/**
 * Parse Unbound log-queries and log-replies lines into dns events.
 * @param {{ device?: (ip: string) => string, now?: () => number, client?: string }} [opts]
 */
function createParser(opts = {}) {
  const deviceFor = opts.device || ((ip) => ip);
  const now = opts.now || (() => 0);
  const client = opts.client || '0.0.0.0';
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      if (typeof line !== 'string' || line.length === 0) return [];
      const query = QUERY.exec(line);
      if (query && line.includes(' query')) {
        return [
          {
            type: 'dns',
            device: deviceFor(client),
            ts: now(),
            qname: trimDot(query[1]),
            qtype: query[2],
            rcode: 'NOERROR',
            resolver: 'unbound',
          },
        ];
      }
      const reply = REPLY.exec(line);
      if (!reply) return [];
      const answers = reply[5]
        ? [reply[5]].slice(0, 8).map((value) => ({ type: reply[2], value, ttl: 0 }))
        : [];
      return [
        {
          type: 'dns',
          device: deviceFor(client),
          ts: now(),
          qname: trimDot(reply[1]),
          qtype: reply[2],
          rcode: reply[4],
          resolver: 'unbound',
          answers,
        },
      ];
    },
  };
}

/**
 * @param {string} name
 */
function trimDot(name) {
  return name.replace(/\.$/, '').toLowerCase();
}

module.exports = { createParser };
