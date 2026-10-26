'use strict';

/** Oldest pending query is dropped once this many names are waiting. */
const PENDING_CAP = 1024;

const QUERY = /query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/;
const REPLY = /reply\s+(\S+)\s+is\s+(\S+)/;
const NX = /reply\s+(\S+)\s+is\s+NXDOMAIN/i;

/**
 * Stream parser for dnsmasq `log-queries=extra` lines.
 * A reply is joined to the latest query for that name.
 * Pending names are capped at 1024; the oldest name is dropped.
 * @param {{ device?: (clientIp: string) => string, resolver?: string, now?: () => number }} [opts]
 */
function createParser(opts = {}) {
  const deviceFor = opts.device || ((ip) => ip);
  const resolver = opts.resolver || 'gateway';
  const now = opts.now || (() => 0);
  /** @type {Map<string, { device: string, qtype: string, client: string }>} */
  const pending = new Map();
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      if (typeof line !== 'string') return [];
      const query = QUERY.exec(line);
      if (query) {
        const name = query[2].toLowerCase();
        if (pending.size >= PENDING_CAP && !pending.has(name)) {
          const oldest = pending.keys().next().value;
          if (oldest != null) pending.delete(oldest);
        }
        pending.set(name, {
          device: deviceFor(query[3]),
          qtype: query[1],
          client: query[3],
        });
        return [];
      }
      const nx = NX.exec(line);
      if (nx) return finish(nx[1], 'NXDOMAIN', []);
      const reply = REPLY.exec(line);
      if (!reply) return [];
      return finish(reply[1], 'NOERROR', [{ type: 'A', value: reply[2], ttl: 0 }]);
    },
  };

  /**
   * @param {string} name
   * @param {string} rcode
   * @param {object[]} answers
   */
  function finish(name, rcode, answers) {
    const key = name.toLowerCase();
    const query = pending.get(key);
    if (!query) return [];
    pending.delete(key);
    return [
      {
        type: 'dns',
        device: query.device,
        ts: now(),
        qname: key,
        qtype: query.qtype,
        rcode,
        resolver,
        answers,
      },
    ];
  }
}

module.exports = { createParser };
