'use strict';

const { HubvikError } = require('../../errors');

const { isIpv6, isMac } = require('../identity');
const { requireFields } = require('./common');

const DISCOVERY_PROTOS = new Set(['mdns', 'ssdp', 'ws-discovery', 'coap']);

const WIFI_OPS = new Set(['assoc', 'disassoc', 'deauth', 'auth-fail', 'probe-resp']);

/**
 * @param {any} raw
 * @param {string} type
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function linkEvent(raw, type, ts, warnings) {
  /** @type {Record<string, any>} */
  const event = { type, tier: 'T4', ts };
  if (type !== 'arp' && type !== 'dhcp' && type !== 'ra') event.device = raw.device;
  else if (raw.device != null) event.device = raw.device;
  if (type === 'arp') {
    requireFields(raw, ['ip', 'mac', 'op'], 'arp');
    event.ip = String(raw.ip);
    event.mac = String(raw.mac).toLowerCase();
    event.op = raw.op;
  } else if (type === 'dhcp') {
    requireFields(raw, ['mac', 'msg'], 'dhcp');
    event.mac = String(raw.mac).toLowerCase();
    event.msg = String(raw.msg);
    if (typeof raw.serverIp === 'string') event.serverIp = raw.serverIp.slice(0, 64);
    if (typeof raw.requestedIp === 'string') event.requestedIp = raw.requestedIp.slice(0, 64);
    if (
      typeof raw.fingerprint === 'string' &&
      raw.fingerprint.length > 0 &&
      raw.fingerprint.length <= 255
    ) {
      event.fingerprint = raw.fingerprint;
    } else if (raw.fingerprint != null) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.fingerprint' });
    }
    if (raw.v6 === true) event.v6 = true;
    else if (raw.v6 != null && raw.v6 !== false) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.v6' });
    }
    if (typeof raw.duid === 'string' && raw.duid.length > 0 && raw.duid.length <= 130) {
      event.duid = raw.duid;
    } else if (raw.duid != null) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.duid' });
    }
    if (Number.isInteger(raw.iaid) && raw.iaid >= 0 && raw.iaid <= 0xffffffff)
      event.iaid = raw.iaid;
    else if (raw.iaid != null)
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.iaid' });
    const options = dhcpOptions(raw.options, warnings);
    if (options) event.options = options;
    const routes = dhcpRoutes(raw.routes, warnings);
    if (routes) event.routes = routes;
    if (typeof raw.wpadUrl === 'string' && raw.wpadUrl.length > 0 && raw.wpadUrl.length <= 255) {
      event.wpadUrl = raw.wpadUrl;
    } else if (raw.wpadUrl != null) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.wpadUrl' });
    }
  } else if (type === 'nd') {
    requireFields(raw, ['ip', 'mac', 'op'], 'nd');
    if (!isIpv6(String(raw.ip))) throw new HubvikError('ND_IP_MUST_BE_IPV6', 'nd.ip must be IPv6');
    const mac = String(raw.mac).toLowerCase();
    if (!isMac(mac)) throw new HubvikError('ND_MAC_IS_INVALID', 'nd.mac is invalid');
    if (raw.op !== 'na' && raw.op !== 'ns' && raw.op !== 'rs' && raw.op !== 'ra') {
      throw new HubvikError('ND_OP_IS_INVALID', 'nd.op is invalid');
    }
    event.ip = String(raw.ip);
    event.mac = mac;
    event.op = raw.op;
    if (raw.router === true) event.router = true;
  } else if (type === 'wifi') {
    requireFields(raw, ['mac', 'op'], 'wifi');
    const mac = String(raw.mac).toLowerCase();
    if (!isMac(mac)) throw new HubvikError('WIFI_MAC_IS_INVALID', 'wifi.mac is invalid');
    if (!WIFI_OPS.has(raw.op)) throw new HubvikError('WIFI_OP_IS_INVALID', 'wifi.op is invalid');
    event.mac = mac;
    event.op = raw.op;
    if (typeof raw.bssid === 'string' && isMac(raw.bssid.toLowerCase())) {
      event.bssid = raw.bssid.toLowerCase();
    } else if (raw.bssid != null) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped wifi.bssid' });
    }
    if (typeof raw.ssid === 'string' && raw.ssid.length > 0 && raw.ssid.length <= 32) {
      event.ssid = raw.ssid;
    } else if (raw.ssid != null) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped wifi.ssid' });
    }
    if (raw.op === 'probe-resp' && !event.ssid) {
      throw new HubvikError('WIFI_SSID_IS_REQUIRED', 'wifi ssid is required');
    }
    if (raw.reason != null) {
      if (Number.isInteger(raw.reason) && raw.reason >= 0 && raw.reason <= 65535) {
        event.reason = raw.reason;
      } else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped wifi.reason' });
    }
  } else if (type === 'ra') {
    requireFields(raw, ['srcMac', 'srcIp'], 'ra');
    event.srcMac = String(raw.srcMac).toLowerCase();
    event.srcIp = String(raw.srcIp);
    event.prefixes = Array.isArray(raw.prefixes) ? raw.prefixes.map(String) : [];
    event.routerLifetime = typeof raw.routerLifetime === 'number' ? raw.routerLifetime : 0;
    if (raw.count == null) event.count = 1;
    else if (Number.isInteger(raw.count) && raw.count >= 1 && raw.count <= 1_000_000) {
      event.count = raw.count;
    } else {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped ra.count' });
      event.count = 1;
    }
  } else {
    requireFields(raw, ['proto', 'srcIp', 'direction'], 'discovery');
    event.srcIp = String(raw.srcIp);
    event.direction = raw.direction;
    if (typeof raw.proto === 'string' && DISCOVERY_PROTOS.has(raw.proto)) event.proto = raw.proto;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped discovery.proto' });
    if (typeof raw.name === 'string' && raw.name.length > 0 && raw.name.length <= 255) {
      event.name = raw.name;
    }
    if (typeof raw.mac === 'string' && isMac(raw.mac.toLowerCase()))
      event.mac = raw.mac.toLowerCase();
  }
  return event;
}

/**
 * @param {unknown} value
 * @param {{ code: string, message: string }[]} warnings
 * @returns {number[] | null}
 */
function dhcpOptions(value, warnings) {
  if (value == null) return null;
  if (!Array.isArray(value) || value.length > 64) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.options' });
    return null;
  }
  /** @type {number[]} */
  const out = [];
  const seen = new Set();
  for (const item of value) {
    if (!Number.isInteger(item) || item < 0 || item > 255) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.options' });
      return null;
    }
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function cidrOk(value) {
  const v4 = /^(\d{1,3}\.){3}\d{1,3}\/(\d{1,2})$/.exec(value);
  if (v4) {
    const bits = Number(v4[2]);
    if (bits > 32) return false;
    return value
      .slice(0, value.indexOf('/'))
      .split('.')
      .every((part) => Number(part) <= 255);
  }
  const v6 = /^[0-9a-f:]+\/(\d{1,3})$/i.exec(value);
  if (!v6 || !value.includes(':')) return false;
  return Number(v6[1]) <= 128;
}

/**
 * @param {unknown} value
 * @param {{ code: string, message: string }[]} warnings
 * @returns {string[] | null}
 */
function dhcpRoutes(value, warnings) {
  if (value == null) return null;
  if (!Array.isArray(value) || value.length > 16) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.routes' });
    return null;
  }
  /** @type {string[]} */
  const out = [];
  for (const item of value) {
    if (typeof item !== 'string' || !cidrOk(item)) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dhcp.routes' });
      return null;
    }
    out.push(item);
  }
  return out;
}

module.exports = { linkEvent };
