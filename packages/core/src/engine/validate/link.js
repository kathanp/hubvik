'use strict';

const { HubvikError } = require('../../errors');

const { isIpv6, isMac } = require('../identity');
const { requireFields } = require('./common');

const DISCOVERY_PROTOS = new Set(['mdns', 'ssdp', 'ws-discovery', 'coap']);

const WIFI_OPS = new Set(['assoc', 'disassoc', 'deauth', 'auth-fail']);

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

module.exports = { linkEvent };
