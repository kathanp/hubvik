'use strict';

// UNVERIFIED: patterns follow OpenWrt logread text for dnsmasq-dhcp, odhcpd, and hostapd.

const DHCP = /DHCPACK\([^)]*\)\s+(\S+)\s+([0-9a-f:]{17})/i;
const DHCPV6 = /dhcpv6\s+(\S+)\s+([0-9a-f:]{17})\s+(\S+)/i;
const ND = /\b(ra|na|ns|rs)\b.*\b([0-9a-f:]{17})\b.*\b([0-9a-f:]+)\b/i;
const WIFI = /STA\s+([0-9a-f:]{17}).*\b(associated|disassociated|deauthenticated|auth-fail)\b/i;

/**
 * Parse OpenWrt logread lines into dhcp, nd, and wifi events.
 * @param {{ device?: (mac: string) => string, now?: () => number }} [opts]
 */
function createParser(opts = {}) {
  const deviceFor = opts.device || ((mac) => mac);
  const now = opts.now || (() => 0);
  return {
    /**
     * @param {string} line
     * @returns {object[]}
     */
    write(line) {
      if (typeof line !== 'string') return [];
      const wifi = WIFI.exec(line);
      if (wifi) {
        const op =
          wifi[2].toLowerCase() === 'associated'
            ? 'assoc'
            : wifi[2].toLowerCase() === 'disassociated'
              ? 'disassoc'
              : wifi[2].toLowerCase() === 'deauthenticated'
                ? 'deauth'
                : 'auth-fail';
        return [
          { type: 'wifi', ts: now(), mac: wifi[1].toLowerCase(), device: deviceFor(wifi[1]), op },
        ];
      }
      const v6 = DHCPV6.exec(line);
      if (v6) {
        return [
          {
            type: 'dhcp',
            ts: now(),
            device: deviceFor(v6[2]),
            mac: v6[2].toLowerCase(),
            msg: 'ack',
            v6: true,
            duid: v6[3].slice(0, 120),
          },
        ];
      }
      const v4 = DHCP.exec(line);
      if (v4) {
        return [
          {
            type: 'dhcp',
            ts: now(),
            device: deviceFor(v4[2]),
            mac: v4[2].toLowerCase(),
            msg: 'ack',
            requestedIp: v4[1],
          },
        ];
      }
      const nd = ND.exec(line);
      if (nd && line.toLowerCase().includes('odhcpd')) {
        return [
          {
            type: 'nd',
            ts: now(),
            device: deviceFor(nd[2]),
            mac: nd[2].toLowerCase(),
            ip: nd[3],
            op: nd[1].toLowerCase(),
          },
        ];
      }
      return [];
    },
  };
}

module.exports = { createParser };
