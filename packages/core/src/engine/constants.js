'use strict';

const SEVERITY = Object.freeze({
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const TIER_SET = new Set(TIERS);
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const ALLOW_KINDS = [
  'dst',
  'port',
  'asn',
  'country',
  'ja4',
  'certIssuer',
  'resolver',
  'peer',
  'fingerprint',
];
const EVENT_TYPES = [
  'summary',
  'flow',
  'dns',
  'tls',
  'http',
  'arp',
  'dhcp',
  'ra',
  'discovery',
  'mapping',
  'app',
  'nd',
  'wifi',
];
const EVENT_TYPE_SET = new Set(EVENT_TYPES);
const SEVERITY_NAMES = new Set(Object.keys(SEVERITY));

const DEFAULTS = {
  learnMs: 7 * 24 * 3600e3,
  windowMs: 60_000,
  tiers: ['T0'],
  maxDevices: 10_000,
  maxDestinations: 5_000,
  maxAlertKeys: 5_000,
  maxWindows: 10_080,
  maxString: 255,
  maxWindowDestinations: 5_000,
  maxIndicators: 1_000_000,
  maxSuppress: 64,
};

module.exports = {
  SEVERITY,
  TIERS,
  TIER_SET,
  FORBIDDEN_KEYS,
  ALLOW_KINDS,
  EVENT_TYPES,
  EVENT_TYPE_SET,
  SEVERITY_NAMES,
  DEFAULTS,
};
