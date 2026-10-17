'use strict';

const { domainToASCII } = require('node:url');
const { TIER_SET, FORBIDDEN_KEYS, SEVERITY_NAMES, DEFAULTS } = require('./constants');
const { ipv4 } = require('./net');

/**
 * @param {string} key
 * @returns {void}
 */
function assertSafeKey(key) {
  if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden key ${key}`);
}

/**
 * @param {object} value
 * @param {string} path
 * @returns {void}
 */
function assertSafeKeys(value, path) {
  if (!value || typeof value !== 'object') return;
  for (const key of Object.keys(value)) {
    if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden key ${key} at ${path}`);
  }
  for (const key of FORBIDDEN_KEYS) {
    if (Object.hasOwn(value, key)) throw new Error(`forbidden key ${key} at ${path}`);
  }
}

/**
 * @param {unknown} value
 * @param {string} name
 * @returns {boolean}
 */
function bool(value, name) {
  if (typeof value !== 'boolean') throw new TypeError(`${name} must be a boolean`);
  return value;
}

/**
 * @param {number} value
 * @param {string} name
 * @param {{ min?: number, max?: number, integer?: boolean }} [rule]
 * @returns {number}
 */
function num(value, name, rule = {}) {
  const min = rule.min ?? 0;
  const max = rule.max ?? Number.POSITIVE_INFINITY;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) {
    throw new TypeError(`${name} must be a finite number >= ${min}`);
  }
  if (rule.integer && !Number.isInteger(value)) throw new TypeError(`${name} must be an integer`);
  return value;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
function isV4(value) {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return false;
    const n = Number(part);
    if (n > 255) return false;
  }
  return true;
}

/**
 * @param {string} ip
 * @returns {string | null}
 */
function normalizeIp(ip) {
  let s = ip.toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped && isV4(mapped[1])) return mapped[1];
  if (s.includes(':') || isV4(s)) return s;
  return null;
}

/**
 * Lowercase, strip a trailing dot, punycode a hostname, unwrap IPv4-mapped IPv6.
 * @param {unknown} value
 * @param {number} maxString
 * @returns {string | null}
 */
function normalizeName(value, maxString) {
  if (typeof value !== 'string') return null;
  let s = value.trim().toLowerCase();
  if (s.endsWith('.')) s = s.slice(0, -1);
  if (!s || s.length > maxString) return null;
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  if (s.includes(':') || isV4(s)) return normalizeIp(s);
  let ascii;
  try {
    ascii = domainToASCII(s);
  } catch {
    return null;
  }
  if (!ascii || ascii.length > maxString) return null;
  return ascii;
}

/**
 * @param {any} raw
 * @returns {{ event: any, warnings: { code: string, message: string }[] }}
 */
function validateEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new TypeError('event must be an object');
  }
  assertSafeKeys(raw, 'event');
  if (typeof raw.device !== 'string' || raw.device.length === 0 || raw.device.length > 255) {
    throw new TypeError('event.device is required');
  }
  if (FORBIDDEN_KEYS.has(raw.device)) throw new TypeError('event.device is reserved');
  /** @type {{ code: string, message: string }[]} */
  const warnings = [];
  let ts;
  if (raw.ts == null) ts = Date.now();
  else if (typeof raw.ts !== 'number' || !Number.isFinite(raw.ts) || raw.ts < 0) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped event.ts' });
    ts = Date.now();
  } else ts = raw.ts;

  const type = raw.type == null ? 'summary' : raw.type;
  if (typeof type !== 'string') throw new TypeError('event.type is invalid');
  if (type === 'summary') return { event: summaryEvent(raw, ts, warnings), warnings };
  if (type === 'flow') return { event: flowEvent(raw, ts, warnings), warnings };
  if (type === 'dns') return { event: dnsEvent(raw, ts, warnings), warnings };
  if (type === 'tls') return { event: tlsEvent(raw, ts, warnings), warnings };
  if (type === 'http') return { event: httpEvent(raw, ts, warnings), warnings };
  if (type === 'arp' || type === 'dhcp' || type === 'ra' || type === 'discovery') {
    return { event: linkEvent(raw, type, ts, warnings), warnings };
  }
  if (type === 'mapping') return { event: mappingEvent(raw, ts), warnings };
  if (type === 'app') return { event: appEvent(raw, ts, warnings), warnings };
  throw new TypeError(`unknown event type ${type}`);
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function summaryEvent(raw, ts, warnings) {
  /** @type {Record<string, any>} */
  const event = { type: 'summary', tier: 'T0', device: raw.device, ts, bytes: 0 };
  if (raw.dst != null) {
    const dst = normalizeName(raw.dst, 255);
    if (dst) event.dst = dst;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped event.dst' });
  }
  if (raw.bytes != null) {
    if (typeof raw.bytes === 'number' && Number.isFinite(raw.bytes) && raw.bytes >= 0) {
      event.bytes = raw.bytes;
    } else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped event.bytes' });
  }
  return event;
}

/**
 * @param {any} raw
 * @param {string[]} fields
 * @param {string} type
 */
function requireFields(raw, fields, type) {
  for (const field of fields) {
    if (raw[field] == null) throw new TypeError(`${type} event requires ${field}`);
  }
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function flowEvent(raw, ts, warnings) {
  requireFields(
    raw,
    [
      'srcIp',
      'srcPort',
      'dstIp',
      'dstPort',
      'proto',
      'direction',
      'bytesOut',
      'bytesIn',
      'pktsOut',
      'pktsIn',
      'durationMs',
    ],
    'flow',
  );
  const direction = raw.direction;
  if (direction !== 'out' && direction !== 'in' && direction !== 'lan') {
    throw new TypeError('flow direction is invalid');
  }
  const proto = raw.proto;
  const protoOk =
    proto === 'tcp' ||
    proto === 'udp' ||
    proto === 'icmp' ||
    proto === 'gre' ||
    proto === 'esp' ||
    (typeof proto === 'number' && proto >= 0);
  if (!protoOk) throw new TypeError('flow proto is invalid');
  /** @type {Record<string, any>} */
  const event = {
    type: 'flow',
    tier: 'T1',
    device: raw.device,
    ts,
    srcIp: String(raw.srcIp),
    srcPort: num(raw.srcPort, 'srcPort', { integer: true, max: 65535 }),
    dstIp: String(raw.dstIp),
    dstPort: num(raw.dstPort, 'dstPort', { integer: true, max: 65535 }),
    proto,
    direction,
    bytesOut: num(raw.bytesOut, 'bytesOut'),
    bytesIn: num(raw.bytesIn, 'bytesIn'),
    pktsOut: num(raw.pktsOut, 'pktsOut'),
    pktsIn: num(raw.pktsIn, 'pktsIn'),
    durationMs: num(raw.durationMs, 'durationMs'),
  };
  if (raw.tcpOutcome != null) {
    const ok = ['established', 'rejected', 'no-response', 'reset'];
    if (ok.includes(raw.tcpOutcome)) event.tcpOutcome = raw.tcpOutcome;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.tcpOutcome' });
  }
  if (raw.icmpType != null) {
    if (Number.isInteger(raw.icmpType) && raw.icmpType >= 0 && raw.icmpType <= 255) {
      event.icmpType = raw.icmpType;
    } else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.icmpType' });
  }
  if (raw.dstName != null) {
    const name = normalizeName(raw.dstName, 255);
    if (name) event.dstName = name;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped flow.dstName' });
  }
  return event;
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function dnsEvent(raw, ts, warnings) {
  requireFields(raw, ['qname', 'qtype', 'rcode', 'resolver'], 'dns');
  const qname = normalizeName(raw.qname, 255);
  if (!qname) throw new TypeError('dns qname is invalid');
  /** @type {Record<string, any>} */
  const event = {
    type: 'dns',
    tier: 'T2',
    device: raw.device,
    ts,
    qname,
    qtype: String(raw.qtype),
    rcode: String(raw.rcode),
    resolver: String(raw.resolver),
  };
  if (raw.answers != null) {
    if (!Array.isArray(raw.answers)) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dns.answers' });
    } else {
      const answers = [];
      for (const answer of raw.answers) {
        if (!answer || typeof answer !== 'object' || typeof answer.type !== 'string') continue;
        answers.push({
          type: answer.type,
          value: answer.value == null ? '' : String(answer.value).slice(0, 255),
          ttl: typeof answer.ttl === 'number' && Number.isFinite(answer.ttl) ? answer.ttl : 0,
        });
      }
      event.answers = answers;
    }
  }
  return event;
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function tlsEvent(raw, ts, warnings) {
  requireFields(raw, ['dstIp', 'dstPort'], 'tls');
  /** @type {Record<string, any>} */
  const event = {
    type: 'tls',
    tier: 'T3',
    device: raw.device,
    ts,
    dstIp: String(raw.dstIp),
    dstPort: num(raw.dstPort, 'dstPort', { integer: true, max: 65535 }),
  };
  if (raw.sni != null) {
    const sni = normalizeName(raw.sni, 255);
    if (sni) event.sni = sni;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped tls.sni' });
  }
  if (raw.ja4 != null) {
    if (typeof raw.ja4 === 'string' && raw.ja4.length <= 255) event.ja4 = raw.ja4;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped tls.ja4' });
  }
  if (typeof raw.version === 'string' && raw.version.length > 0 && raw.version.length <= 32) {
    event.version = raw.version;
  } else if (raw.version != null) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped tls.version' });
  }
  if (Array.isArray(raw.alpn)) {
    event.alpn = raw.alpn
      .filter(
        (/** @type {unknown} */ item) =>
          typeof item === 'string' && item.length > 0 && item.length <= 32,
      )
      .slice(0, 8);
  }
  if (raw.cert && typeof raw.cert === 'object' && !Array.isArray(raw.cert)) {
    /** @type {Record<string, any>} */
    const cert = {};
    if (typeof raw.cert.issuer === 'string') cert.issuer = raw.cert.issuer.slice(0, 255);
    if (typeof raw.cert.subject === 'string') cert.subject = raw.cert.subject.slice(0, 255);
    if (typeof raw.cert.sha256 === 'string') cert.sha256 = raw.cert.sha256.slice(0, 64);
    if (typeof raw.cert.selfSigned === 'boolean') cert.selfSigned = raw.cert.selfSigned;
    if (typeof raw.cert.notAfter === 'number' && Number.isFinite(raw.cert.notAfter)) {
      cert.notAfter = raw.cert.notAfter;
    }
    event.cert = cert;
  }
  return event;
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function httpEvent(raw, ts, warnings) {
  requireFields(raw, ['dstIp', 'dstPort', 'method'], 'http');
  /** @type {Record<string, any>} */
  const event = {
    type: 'http',
    tier: 'T3',
    device: raw.device,
    ts,
    dstIp: String(raw.dstIp),
    dstPort: num(raw.dstPort, 'dstPort', { integer: true, max: 65535 }),
    method: String(raw.method).slice(0, 32),
  };
  if (raw.host != null) {
    const host = normalizeName(raw.host, 255);
    if (host) event.host = host;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped http.host' });
  }
  if (typeof raw.path === 'string') event.path = raw.path.slice(0, 255);
  return event;
}

const DISCOVERY_PROTOS = new Set(['mdns', 'ssdp', 'ws-discovery', 'coap']);

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
  }
  return event;
}

const APP_PROTOS = new Set([
  'bacnet',
  'modbus',
  'dnp3',
  'knx',
  's7',
  'enip',
  'mqtt',
  'coap',
  'rtsp',
  'onvif',
  'stratum',
  'smtp',
]);

/**
 * Host-reported UPnP, NAT-PMP, or PCP mapping.
 * @param {any} raw
 * @param {number} ts
 */
function mappingEvent(raw, ts) {
  requireFields(raw, ['proto', 'port'], 'mapping');
  if (raw.proto !== 'upnp' && raw.proto !== 'nat-pmp' && raw.proto !== 'pcp') {
    throw new TypeError('mapping proto is invalid');
  }
  /** @type {Record<string, any>} */
  const event = {
    type: 'mapping',
    tier: 'T1',
    device: raw.device,
    ts,
    proto: raw.proto,
    port: num(raw.port, 'port', { integer: true, max: 65535 }),
  };
  if (raw.externalPort != null) {
    event.externalPort = num(raw.externalPort, 'externalPort', { integer: true, max: 65535 });
  }
  return event;
}

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function appEvent(raw, ts, warnings) {
  requireFields(raw, ['proto', 'role', 'peerIp', 'op'], 'app');
  if (!APP_PROTOS.has(raw.proto)) throw new TypeError('app proto is invalid');
  if (raw.role !== 'client' && raw.role !== 'server') throw new TypeError('app role is invalid');
  /** @type {Record<string, any>} */
  const event = {
    type: 'app',
    tier: 'T5',
    device: raw.device,
    ts,
    proto: raw.proto,
    role: raw.role,
    peerIp: String(raw.peerIp),
    op: String(raw.op).slice(0, 255),
  };
  if (raw.target != null) event.target = String(raw.target).slice(0, 255);
  if (typeof raw.value === 'number' || typeof raw.value === 'string') event.value = raw.value;
  else if (raw.value != null)
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped app.value' });
  if (raw.result === 'ok' || raw.result === 'error' || raw.result === 'reject')
    event.result = raw.result;
  return event;
}

/** @param {number} ts */
function defaultHour(ts) {
  return new Date(ts).getUTCHours();
}

/** @param {number} ts */
function defaultDay(ts) {
  return Math.floor(ts / 86400000);
}

/**
 * @param {any} [raw]
 */
function validateOptions(raw) {
  const input = raw ?? {};
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('options must be an object');
  }
  assertSafeKeys(input, 'options');
  const tiers = input.tiers == null ? DEFAULTS.tiers.slice() : input.tiers;
  if (!Array.isArray(tiers) || tiers.length === 0 || tiers.some((tier) => !TIER_SET.has(tier))) {
    throw new TypeError('tiers must list one or more of T0..T5');
  }
  /** @type {Record<string, any>} */
  const detectors = {};
  if (input.detectors != null) {
    if (!input.detectors || typeof input.detectors !== 'object' || Array.isArray(input.detectors)) {
      throw new TypeError('detectors must be an object');
    }
    assertSafeKeys(input.detectors, 'detectors');
    for (const [id, value] of Object.entries(input.detectors)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new TypeError(`detectors.${id} must be an object`);
      }
      assertSafeKeys(value, `detectors.${id}`);
      if (value.enabled != null && typeof value.enabled !== 'boolean') {
        throw new TypeError(`detectors.${id}.enabled must be boolean`);
      }
      if (value.severity != null && !SEVERITY_NAMES.has(value.severity)) {
        throw new TypeError(`detectors.${id}.severity is invalid`);
      }
      detectors[id] = value;
    }
  }
  if (input.hourOf != null && typeof input.hourOf !== 'function') {
    throw new TypeError('hourOf must be a function');
  }
  if (input.dayOf != null && typeof input.dayOf !== 'function') {
    throw new TypeError('dayOf must be a function');
  }
  return {
    learnMs: input.learnMs == null ? DEFAULTS.learnMs : num(input.learnMs, 'learnMs', { min: 0 }),
    reorderMs:
      input.reorderMs == null ? 0 : num(input.reorderMs, 'reorderMs', { min: 0, integer: true }),
    minLearnWindows:
      input.minLearnWindows == null
        ? 0
        : num(input.minLearnWindows, 'minLearnWindows', { min: 0, integer: true }),
    tierSilentMs:
      input.tierSilentMs == null
        ? 6 * 3600e3
        : num(input.tierSilentMs, 'tierSilentMs', { min: 1, integer: true }),
    evidence: input.evidence == null ? true : bool(input.evidence, 'evidence'),
    windowMs:
      input.windowMs == null
        ? DEFAULTS.windowMs
        : num(input.windowMs, 'windowMs', { min: 1, integer: true }),
    tiers: [...new Set(tiers)],
    maxDevices:
      input.maxDevices == null
        ? DEFAULTS.maxDevices
        : num(input.maxDevices, 'maxDevices', { min: 1, integer: true }),
    maxDestinations:
      input.maxDestinations == null
        ? DEFAULTS.maxDestinations
        : num(input.maxDestinations, 'maxDestinations', { min: 1, integer: true }),
    maxAlertKeys:
      input.maxAlertKeys == null
        ? DEFAULTS.maxAlertKeys
        : num(input.maxAlertKeys, 'maxAlertKeys', { min: 1, integer: true }),
    maxWindows:
      input.maxWindows == null
        ? DEFAULTS.maxWindows
        : num(input.maxWindows, 'maxWindows', { min: 1, integer: true }),
    maxString:
      input.maxString == null
        ? DEFAULTS.maxString
        : num(input.maxString, 'maxString', { min: 1, integer: true }),
    maxWindowDestinations:
      input.maxWindowDestinations == null
        ? DEFAULTS.maxWindowDestinations
        : num(input.maxWindowDestinations, 'maxWindowDestinations', { min: 1, integer: true }),
    maxIndicators:
      input.maxIndicators == null
        ? DEFAULTS.maxIndicators
        : num(input.maxIndicators, 'maxIndicators', { min: 1, integer: true }),
    sigma: input.sigma == null ? undefined : num(input.sigma, 'sigma', { min: 0 }),
    minBytes: input.minBytes == null ? undefined : num(input.minBytes, 'minBytes', { min: 0 }),
    minFanout:
      input.minFanout == null
        ? undefined
        : num(input.minFanout, 'minFanout', { min: 1, integer: true }),
    fanoutFactor:
      input.fanoutFactor == null ? undefined : num(input.fanoutFactor, 'fanoutFactor', { min: 0 }),
    peakFactor:
      input.peakFactor == null ? undefined : num(input.peakFactor, 'peakFactor', { min: 0 }),
    maxNewDstPerWindow:
      input.maxNewDstPerWindow == null
        ? undefined
        : num(input.maxNewDstPerWindow, 'maxNewDstPerWindow', { min: 0, integer: true }),
    hourOf: input.hourOf ?? defaultHour,
    dayOf: input.dayOf ?? defaultDay,
    detectors,
    policy: parsePolicy(input),
    lookup: parseLookup(input),
    gatewayIp: parseOptionalString(input.gatewayIp, 'gatewayIp'),
    dhcpServers: parseStringList(input.dhcpServers, 'dhcpServers'),
    routers: parseStringList(input.routers, 'routers'),
    browserJa4: parseStringList(input.browserJa4, 'browserJa4'),
    zones: parseZones(input),
    incidentWindowMs:
      input.incidentWindowMs == null
        ? 30 * 60 * 1000
        : num(input.incidentWindowMs, 'incidentWindowMs', { min: 1, integer: true }),
    explicit: new Set(Object.keys(input)),
    raw: input,
  };
}

/**
 * @param {any} input
 * @returns {any[]}
 */
/**
 * @param {any} input
 */
function parseLookup(input) {
  if (input.lookup == null) return null;
  if (typeof input.lookup !== 'function') throw new TypeError('lookup must be a function');
  return input.lookup;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string | null}
 */
function parseOptionalString(value, label) {
  if (value == null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string[]}
 */
function parseStringList(value, label) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length > 32) throw new TypeError(`${label} is invalid`);
  return value.map((item) => {
    if (typeof item !== 'string' || item.length === 0 || item.length > 255) {
      throw new TypeError(`${label} is invalid`);
    }
    return item;
  });
}

/**
 * @param {any} input
 * @returns {{ id: string, base: number, bits: number }[]}
 */
function parseZones(input) {
  if (input.zones == null) return [];
  if (!Array.isArray(input.zones) || input.zones.length > 64) {
    throw new TypeError('zones are invalid');
  }
  return input.zones.map((/** @type {any} */ zone, /** @type {number} */ index) => {
    if (!zone || typeof zone !== 'object' || Array.isArray(zone)) {
      throw new TypeError('zone is invalid');
    }
    assertSafeKeys(zone, `zones[${index}]`);
    if (typeof zone.id !== 'string' || !/^[a-z0-9-]+$/.test(zone.id)) {
      throw new TypeError('zone id is invalid');
    }
    const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(String(zone.cidr || ''));
    const base = match ? ipv4(match[1]) : null;
    const bits = match ? Number(match[2]) : -1;
    if (base == null || bits < 0 || bits > 32) throw new TypeError('zone cidr is invalid');
    return { id: zone.id, base, bits };
  });
}

/**
 * @param {any} input
 * @returns {any[]}
 */
function parsePolicy(input) {
  if (input.policy == null) return [];
  if (!Array.isArray(input.policy)) throw new TypeError('policy must be an array');
  if (input.policy.length > 256) throw new TypeError('policy exceeds cap');
  return input.policy.map((/** @type {any} */ rule, /** @type {number} */ index) => {
    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      throw new TypeError('policy rule is invalid');
    }
    assertSafeKeys(rule, `policy[${index}]`);
    if (typeof rule.id !== 'string' || !/^[a-z0-9-]+$/.test(rule.id)) {
      throw new TypeError('policy id is invalid');
    }
    if (!rule.match || typeof rule.match !== 'object' || Array.isArray(rule.match)) {
      throw new TypeError('policy match is invalid');
    }
    assertSafeKeys(rule.match, `policy[${index}].match`);
    if (rule.severity != null && !SEVERITY_NAMES.has(rule.severity)) {
      throw new TypeError('policy severity is invalid');
    }
    return { id: rule.id, severity: rule.severity, match: rule.match };
  });
}

/**
 * @param {any} raw
 * @returns {{ value: string, type: string, source: string, confidence: number, expiresTs: number | null }}
 */
function validateIndicator(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new TypeError('indicator must be an object');
  assertSafeKeys(raw, 'indicator');
  const types = new Set(['ip', 'cidr', 'domain', 'ja4', 'tor', 'ad', 'proxy-sdk']);
  if (typeof raw.value !== 'string' || raw.value.length === 0 || raw.value.length > 255) {
    throw new TypeError('indicator.value is invalid');
  }
  if (!types.has(raw.type)) throw new TypeError('indicator.type is invalid');
  if (typeof raw.source !== 'string' || raw.source.length === 0 || raw.source.length > 255) {
    throw new TypeError('indicator.source is invalid');
  }
  const confidence =
    raw.confidence == null ? 1 : num(raw.confidence, 'indicator.confidence', { max: 1 });
  let expiresTs = null;
  if (raw.expiresTs != null) expiresTs = num(raw.expiresTs, 'indicator.expiresTs');
  if (raw.type === 'ip' && !normalizeIp(raw.value)) throw new TypeError('indicator ip is invalid');
  if (raw.type === 'cidr' && !/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(raw.value)) {
    throw new TypeError('indicator cidr is invalid');
  }
  return { value: raw.value, type: raw.type, source: raw.source, confidence, expiresTs };
}

module.exports = {
  assertSafeKey,
  assertSafeKeys,
  normalizeName,
  normalizeIp,
  validateEvent,
  validateOptions,
  validateIndicator,
  num,
};
