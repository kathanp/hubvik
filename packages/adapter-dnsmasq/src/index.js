'use strict';

const QUERY = /query\[(\w+)\]\s+(\S+)\s+from\s+(\S+)/;
const REPLY = /reply\s+(\S+)\s+is\s+(\S+)/;
const NX = /reply\s+(\S+)\s+is\s+NXDOMAIN/i;

/**
 * Stream parser for dnsmasq `log-queries=extra` lines.
 * A reply is joined to the latest query for that name.
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
      const query = QUERY.exec(line);
      if (query) {
        pending.set(query[2].toLowerCase(), {
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
