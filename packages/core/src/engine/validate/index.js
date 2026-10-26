'use strict';

const { HubvikError } = require('../../errors');

const { TIER_SET, FORBIDDEN_KEYS, SEVERITY_NAMES, DEFAULTS } = require('../constants');
const {
  assertSafeKey,
  assertSafeKeys,
  normalizeName,
  normalizeIp,
  num,
  bool,
  identityMode,
  parsePromote,
  parseShadow,
  tierLimits,
  parsePolicy,
  parseLookup,
  parseOptionalString,
  parseStringList,
  parseZones,
  defaultHour,
  defaultDay,
} = require('./common');
const { summaryEvent, flowEvent } = require('./flow');
const { dnsEvent } = require('./dns');
const { tlsEvent } = require('./tls');
const { httpEvent, mappingEvent, appEvent } = require('./app');
const { linkEvent } = require('./link');

/**
 * @param {any} raw
 * @returns {{ event: any, warnings: { code: string, message: string }[] }}
 */
function validateEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('EVENT_MUST_BE_AN_OBJECT', 'event must be an object');
  }
  assertSafeKeys(raw, 'event');
  if (typeof raw.device !== 'string' || raw.device.length === 0 || raw.device.length > 255) {
    throw new HubvikError('EVENT_DEVICE_IS_REQUIRED', 'event.device is required');
  }
  if (FORBIDDEN_KEYS.has(raw.device))
    throw new HubvikError('EVENT_DEVICE_IS_RESERVED', 'event.device is reserved');
  /** @type {{ code: string, message: string }[]} */
  const warnings = [];
  let ts;
  if (raw.ts == null) ts = Date.now();
  else if (typeof raw.ts !== 'number' || !Number.isFinite(raw.ts) || raw.ts < 0) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped event.ts' });
    ts = Date.now();
  } else ts = raw.ts;

  const type = raw.type == null ? 'summary' : raw.type;
  if (typeof type !== 'string')
    throw new HubvikError('EVENT_TYPE_IS_INVALID', 'event.type is invalid');
  if (type === 'summary') return { event: summaryEvent(raw, ts, warnings), warnings };
  if (type === 'flow') return { event: flowEvent(raw, ts, warnings), warnings };
  if (type === 'dns') return { event: dnsEvent(raw, ts, warnings), warnings };
  if (type === 'tls') return { event: tlsEvent(raw, ts, warnings), warnings };
  if (type === 'http') return { event: httpEvent(raw, ts, warnings), warnings };
  if (
    type === 'arp' ||
    type === 'dhcp' ||
    type === 'ra' ||
    type === 'discovery' ||
    type === 'nd' ||
    type === 'wifi'
  ) {
    return { event: linkEvent(raw, type, ts, warnings), warnings };
  }
  if (type === 'mapping') return { event: mappingEvent(raw, ts), warnings };
  if (type === 'app') return { event: appEvent(raw, ts, warnings), warnings };
  throw new HubvikError('UNKNOWN_EVENT_TYPE', `unknown event type ${type}`);
}

/**
 * @param {any} [raw]
 */
function validateOptions(raw) {
  const input = raw ?? {};
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new HubvikError('OPTIONS_MUST_BE_AN_OBJECT', 'options must be an object');
  }
  assertSafeKeys(input, 'options');
  const tiers = input.tiers == null ? DEFAULTS.tiers.slice() : input.tiers;
  if (!Array.isArray(tiers) || tiers.length === 0 || tiers.some((tier) => !TIER_SET.has(tier))) {
    throw new HubvikError(
      'TIERS_MUST_LIST_ONE_OR_MORE_OF_T0_T5',
      'tiers must list one or more of T0..T5',
    );
  }
  /** @type {Record<string, any>} */
  const detectors = {};
  if (input.detectors != null) {
    if (!input.detectors || typeof input.detectors !== 'object' || Array.isArray(input.detectors)) {
      throw new HubvikError('DETECTORS_MUST_BE_AN_OBJECT', 'detectors must be an object');
    }
    assertSafeKeys(input.detectors, 'detectors');
    for (const [id, value] of Object.entries(input.detectors)) {
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new HubvikError('DETECTORS_MUST_BE_AN_OBJECT_2', `detectors.${id} must be an object`);
      }
      assertSafeKeys(value, `detectors.${id}`);
      if (value.enabled != null && typeof value.enabled !== 'boolean') {
        throw new HubvikError(
          'DETECTORS_ENABLED_MUST_BE_BOOLEAN',
          `detectors.${id}.enabled must be boolean`,
        );
      }
      if (value.severity != null && !SEVERITY_NAMES.has(value.severity)) {
        throw new HubvikError(
          'DETECTORS_SEVERITY_IS_INVALID',
          `detectors.${id}.severity is invalid`,
        );
      }
      if (value.mode != null && value.mode !== 'live' && value.mode !== 'shadow') {
        throw new HubvikError(
          'DETECTORS_MODE_MUST_BE_LIVE_OR_SHADOW',
          `detectors.${id}.mode must be live or shadow`,
        );
      }
      if (value.canary != null) {
        if (!value.canary || typeof value.canary !== 'object' || Array.isArray(value.canary)) {
          throw new HubvikError(
            'DETECTORS_CANARY_MUST_BE_AN_OBJECT',
            `detectors.${id}.canary must be an object`,
          );
        }
        assertSafeKeys(value.canary, `detectors.${id}.canary`);
      }
      detectors[id] = value;
    }
  }
  if (input.hourOf != null && typeof input.hourOf !== 'function') {
    throw new HubvikError('HOUROF_MUST_BE_A_FUNCTION', 'hourOf must be a function');
  }
  if (input.dayOf != null && typeof input.dayOf !== 'function') {
    throw new HubvikError('DAYOF_MUST_BE_A_FUNCTION', 'dayOf must be a function');
  }
  return {
    learnMs: input.learnMs == null ? DEFAULTS.learnMs : num(input.learnMs, 'learnMs', { min: 0 }),
    reorderMs:
      input.reorderMs == null ? 0 : num(input.reorderMs, 'reorderMs', { min: 0, integer: true }),
    maxBuffered:
      input.maxBuffered == null
        ? 50_000
        : num(input.maxBuffered, 'maxBuffered', { min: 1, integer: true }),
    minLearnWindows:
      input.minLearnWindows == null
        ? 0
        : num(input.minLearnWindows, 'minLearnWindows', { min: 0, integer: true }),
    tierSilentMs:
      input.tierSilentMs == null
        ? 6 * 3600e3
        : num(input.tierSilentMs, 'tierSilentMs', { min: 1, integer: true }),
    tierSilentByTier: tierLimits(input.tierSilentByTier),
    evidence: input.evidence == null ? true : bool(input.evidence, 'evidence'),
    explainCap:
      input.explainCap == null
        ? 1_000
        : num(input.explainCap, 'explainCap', { min: 1, integer: true }),
    identity: input.identity == null ? 'off' : identityMode(input.identity),
    promote: parsePromote(input),
    horizons: input.horizons == null ? null : bool(input.horizons, 'horizons'),
    graph: input.graph == null ? null : bool(input.graph, 'graph'),
    campaigns: input.campaigns == null ? false : bool(input.campaigns, 'campaigns'),
    shadow: parseShadow(input.shadow),
    linkMs: input.linkMs == null ? 900000 : num(input.linkMs, 'linkMs', { min: 1, integer: true }),
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
    ownBssids: parseStringList(input.ownBssids, 'ownBssids'),
    browserJa4: parseStringList(input.browserJa4, 'browserJa4'),
    zones: parseZones(input),
    budget: parseBudget(input.budget),
    calibratedConfidence:
      input.calibratedConfidence == null
        ? false
        : bool(input.calibratedConfidence, 'calibratedConfidence'),
    classSuggest: input.classSuggest == null ? false : bool(input.classSuggest, 'classSuggest'),
    responseHints: input.responseHints == null ? false : bool(input.responseHints, 'responseHints'),
    scoring: parseScoring(input.scoring),
    alerts: input.alerts == null ? false : bool(input.alerts, 'alerts'),
    drift: input.drift == null ? false : bool(input.drift, 'drift'),
    audit: input.audit == null ? false : bool(input.audit, 'audit'),
    peerSuggest: input.peerSuggest == null ? false : bool(input.peerSuggest, 'peerSuggest'),
    outlier: input.outlier == null ? false : bool(input.outlier, 'outlier'),
    sequence: input.sequence == null ? false : bool(input.sequence, 'sequence'),
    flowShape: input.flowShape == null ? false : bool(input.flowShape, 'flowShape'),
    fdr: input.fdr == null ? false : bool(input.fdr, 'fdr'),
    correlate: input.correlate == null ? false : bool(input.correlate, 'correlate'),
    redact: parseRedact(input.redact),
    incidentWindowMs:
      input.incidentWindowMs == null
        ? 30 * 60 * 1000
        : num(input.incidentWindowMs, 'incidentWindowMs', { min: 1, integer: true }),
    explicit: new Set(Object.keys(input)),
    raw: input,
  };
}

/**
 * @param {any} raw
 * @returns {{ value: string, type: string, source: string, confidence: number, expiresTs: number | null }}
 */
function validateIndicator(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new HubvikError('INDICATOR_MUST_BE_AN_OBJECT', 'indicator must be an object');
  assertSafeKeys(raw, 'indicator');
  const types = new Set([
    'ip',
    'cidr',
    'domain',
    'ja4',
    'tor',
    'ad',
    'tracker',
    'proxy-sdk',
    'young-domain',
  ]);
  if (typeof raw.value !== 'string' || raw.value.length === 0 || raw.value.length > 255) {
    throw new HubvikError('INDICATOR_VALUE_IS_INVALID', 'indicator.value is invalid');
  }
  if (!types.has(raw.type))
    throw new HubvikError('INDICATOR_TYPE_IS_INVALID', 'indicator.type is invalid');
  if (typeof raw.source !== 'string' || raw.source.length === 0 || raw.source.length > 255) {
    throw new HubvikError('INDICATOR_SOURCE_IS_INVALID', 'indicator.source is invalid');
  }
  const confidence =
    raw.confidence == null ? 1 : num(raw.confidence, 'indicator.confidence', { max: 1 });
  let expiresTs = null;
  if (raw.expiresTs != null) expiresTs = num(raw.expiresTs, 'indicator.expiresTs');
  const ip = raw.type === 'ip' ? normalizeIp(raw.value) : null;
  if (raw.type === 'ip' && !ip)
    throw new HubvikError('INDICATOR_IP_IS_INVALID', 'indicator ip is invalid');
  if (raw.type === 'cidr' && !/^(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(raw.value)) {
    throw new HubvikError('INDICATOR_CIDR_IS_INVALID', 'indicator cidr is invalid');
  }
  return {
    value: ip || raw.value,
    type: raw.type,
    source: raw.source,
    confidence,
    expiresTs,
  };
}

/**
 * @param {any} value
 */
function parseBudget(value) {
  if (value == null || value === false) return null;
  const input = value === true ? {} : value;
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new HubvikError('BUDGET_MUST_BE_AN_OBJECT', 'budget must be an object');
  }
  assertSafeKeys(input, 'budget');
  if (input.clock != null && typeof input.clock !== 'function') {
    throw new HubvikError('BUDGET_CLOCK_MUST_BE_A_FUNCTION', 'budget.clock must be a function');
  }
  return {
    perEventUs:
      input.perEventUs == null ? 50 : num(input.perEventUs, 'budget.perEventUs', { min: 1 }),
    sampleEvery:
      input.sampleEvery == null
        ? 64
        : num(input.sampleEvery, 'budget.sampleEvery', { min: 1, integer: true }),
    recoverWindows:
      input.recoverWindows == null
        ? 5
        : num(input.recoverWindows, 'budget.recoverWindows', { min: 1, integer: true }),
    clock: input.clock || (() => process.hrtime.bigint()),
  };
}

/**
 * @param {unknown} value
 * @returns {'additive' | 'lr'}
 */
function parseScoring(value) {
  if (value == null) return 'additive';
  if (value === 'additive' || value === 'lr') return value;
  throw new HubvikError('SCORING_IS_INVALID', 'scoring is invalid');
}

/**
 * @param {any} value
 */
function parseRedact(value) {
  if (value == null || value === false) return null;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HubvikError('REDACT_MUST_BE_AN_OBJECT', 'redact must be an object');
  }
  assertSafeKeys(value, 'redact');
  if (typeof value.key !== 'string' && !Buffer.isBuffer(value.key)) {
    throw new HubvikError('REDACT_KEY_IS_INVALID', 'redact.key is invalid');
  }
  const fields = Array.isArray(value.fields)
    ? value.fields
    : ['device', 'dst', 'qname', 'sni', 'srcIp', 'dstIp', 'mac'];
  if (fields.some((/** @type {unknown} */ field) => typeof field !== 'string'))
    throw new HubvikError('REDACT_FIELDS_IS_INVALID', 'redact.fields is invalid');
  if (value.redactMap != null && typeof value.redactMap !== 'function') {
    throw new HubvikError(
      'REDACT_REDACTMAP_MUST_BE_A_FUNCTION',
      'redact.redactMap must be a function',
    );
  }
  return { key: value.key, fields, map: value.redactMap || null };
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
