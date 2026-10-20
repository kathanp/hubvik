'use strict';

// UNVERIFIED: SSDP request lines from a passive listener.

/**
 * Parse passive SSDP lines into discovery and UPnP app events.
 * @param {{ device?: string, now?: () => number, srcIp?: string }} [opts]
 */
function createParser(opts = {}) {
  const device = opts.device || 'lan';
  const now = opts.now || (() => 0);
  const srcIp = opts.srcIp || '192.0.2.10';
  return {
    /**
     * @param {string} text
     * @returns {object[]}
     */
    write(text) {
      if (typeof text !== 'string' || text.length === 0) return [];
      const first = text.split('\n')[0].trim();
      if (first.startsWith('NOTIFY') || first.startsWith('M-SEARCH')) {
        const name = header(text, 'NT') || header(text, 'ST') || 'ssdp';
        return [
          {
            type: 'discovery',
            ts: now(),
            device,
            proto: 'ssdp',
            srcIp,
            direction: 'lan',
            name,
          },
        ];
      }
      if (!first.startsWith('SUBSCRIBE')) return [];
      const callback = header(text, 'CALLBACK') || '';
      const host = callback
        .replace(/[<>]/g, '')
        .replace(/^https?:\/\//, '')
        .split(':')[0]
        .split('/')[0];
      return [
        {
          type: 'app',
          ts: now(),
          device,
          proto: 'upnp',
          role: 'client',
          peerIp: host || srcIp,
          op: 'SUBSCRIBE',
          target: host,
        },
      ];
    },
  };
}

/**
 * @param {string} text
 * @param {string} name
 */
function header(text, name) {
  const match = new RegExp(`^${name}:\\s*(.+)$`, 'im').exec(text);
  return match ? match[1].trim() : '';
}

module.exports = { createParser };
