'use strict';

const { assertSafeKeys } = require('./validate');
const { exportHorizon, importHorizon } = require('./horizon');
const { LruSet, SampleRing } = require('./caps');

const MAX_BYTES = 16 * 1024 * 1024;
const KNOWN = new Set([
  'arp-spoof',
  'identity-change',
  'identity',
  'dhcp-starvation',
  'fleet-wave',
  'nd-spoof',
  'wifi-deauth-flood',
]);

/**
 * @param {unknown} value
 * @returns {any}
 */
function plain(value) {
  if (value instanceof Float64Array) {
    return {
      f64: Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('base64'),
    };
  }
  if (value instanceof LruSet) return { lru: value.max, values: value.toArray() };
  if (value instanceof SampleRing) return { ring: value.max, values: value.toArray() };
  if (value instanceof Map)
    return { map: [...value.entries()].map((pair) => [pair[0], plain(pair[1])]) };
  if (value instanceof Set) return { set: [...value].map(plain) };
  if (Array.isArray(value)) return value.map(plain);
  if (value && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for (const key of Object.keys(value)) out[key] = plain(/** @type {any} */ (value)[key]);
    return out;
  }
  return value;
}

/**
 * @param {any} value
 * @returns {any}
 */
function revive(value) {
  if (Array.isArray(value)) return value.map(revive);
  if (!value || typeof value !== 'object') return value;
  if (typeof value.f64 === 'string' && Object.keys(value).length === 1) {
    const bytes = Buffer.from(value.f64, 'base64');
    if (bytes.length % 8 !== 0) throw new Error('checkpoint state is invalid');
    const out = new Float64Array(bytes.length / 8);
    new Uint8Array(out.buffer).set(bytes);
    return out;
  }
  const keys = Object.keys(value);
  const tagged = keys.some(
    (key) => key === 'set' || key === 'map' || key === 'lru' || key === 'ring',
  );
  if (keys.length === 1 && keys[0] === 'map' && Array.isArray(value.map)) {
    return new Map(value.map.map((/** @type {any[]} */ pair) => [pair[0], revive(pair[1])]));
  }
  if (keys.length === 1 && keys[0] === 'set' && Array.isArray(value.set)) {
    return new Set(value.set.map(revive));
  }
  if (
    keys.length === 2 &&
    typeof value.lru === 'number' &&
    Array.isArray(value.values) &&
    keys.includes('lru')
  ) {
    const set = new LruSet(value.lru);
    for (const item of value.values) set.add(item);
    return set;
  }
  if (
    keys.length === 2 &&
    typeof value.ring === 'number' &&
    Array.isArray(value.values) &&
    keys.includes('ring')
  ) {
    const ring = new SampleRing(value.ring);
    for (const item of value.values) ring.push(item);
    return ring;
  }
  if (tagged) throw new Error('checkpoint state is invalid');
  /** @type {Record<string, unknown>} */
  const out = {};
  for (const key of keys) out[key] = revive(value[key]);
  return out;
}

/**
 * @param {Map<string, any>} scratch
 */
function plainScratch(scratch) {
  /** @type {Record<string, unknown>} */
  const out = {};
  for (const [key, value] of scratch) {
    if (!KNOWN.has(key)) continue;
    out[key] = plain(value);
  }
  return out;
}

/**
 * @param {any} raw
 */
function assertCheckpoint(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error('unsupported checkpoint');
  assertSafeKeys(raw, 'checkpoint');
  if (
    raw.watermark != null &&
    (typeof raw.watermark !== 'number' || !Number.isFinite(raw.watermark))
  ) {
    throw new Error('checkpoint watermark is invalid');
  }
  if (raw.scratch == null) return;
  if (typeof raw.scratch !== 'object' || Array.isArray(raw.scratch)) {
    throw new Error('checkpoint scratch is invalid');
  }
  assertSafeKeys(raw.scratch, 'scratch');
  for (const key of Object.keys(raw.scratch)) {
    if (!KNOWN.has(key)) throw new Error(`unknown scratch table ${key}`);
  }
}

/**
 * Reject a revived scratch table whose shape would crash a later feed.
 * @param {any} scratch
 * @returns {void}
 */
function assertRevived(scratch) {
  const wave = scratch['fleet-wave'];
  if (wave != null) {
    if (!(wave instanceof Map)) throw new Error('checkpoint scratch fleet-wave is invalid');
    for (const row of wave.values()) {
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        throw new Error('checkpoint scratch fleet-wave is invalid');
      }
      if (!(row.devices instanceof Map) || typeof row.first !== 'number') {
        throw new Error('checkpoint scratch fleet-wave is invalid');
      }
    }
  }
  const arp = scratch['arp-spoof'];
  if (arp != null) {
    if (typeof arp !== 'object' || !(arp.bindings instanceof Map) || !(arp.macIps instanceof Map)) {
      throw new Error('checkpoint scratch arp-spoof is invalid');
    }
  }
  const learnedMacs = scratch['identity-change'];
  if (learnedMacs != null) {
    if (typeof learnedMacs !== 'object' || !(learnedMacs.macs instanceof Map)) {
      throw new Error('checkpoint scratch identity-change is invalid');
    }
  }
  const bindings = scratch.identity;
  if (bindings != null) {
    if (!(bindings instanceof Map)) throw new Error('checkpoint scratch identity is invalid');
    if (bindings.size > 50_000) throw new Error('array identity exceeds cap');
    for (const row of bindings.values()) {
      if (!row || typeof row.mac !== 'string' || typeof row.lastTs !== 'number') {
        throw new Error('checkpoint scratch identity is invalid');
      }
      if (row.source !== 'dhcp' && row.source !== 'arp' && row.source !== 'nd') {
        throw new Error('checkpoint scratch identity is invalid');
      }
    }
  }
  const nd = scratch['nd-spoof'];
  if (nd != null) {
    if (typeof nd !== 'object' || !(nd.bindings instanceof Map)) {
      throw new Error('checkpoint scratch nd-spoof is invalid');
    }
    if (nd.bindings.size > 5000) throw new Error('array bindings exceeds cap');
  }
  const wifi = scratch['wifi-deauth-flood'];
  if (wifi != null) {
    if (typeof wifi !== 'object' || !(wifi.byMac instanceof Map)) {
      throw new Error('checkpoint scratch wifi-deauth-flood is invalid');
    }
  }
  const dhcp = scratch['dhcp-starvation'];
  if (dhcp != null) {
    if (typeof dhcp !== 'object' || !(dhcp.macs instanceof Set)) {
      throw new Error('checkpoint scratch dhcp-starvation is invalid');
    }
  }
}

/**
 * Drop the oldest ARP binding, then the oldest learned MAC, until the body fits.
 * @param {any} body
 * @returns {boolean}
 */
function fit(body) {
  let truncated = false;
  let text = JSON.stringify(body);
  while (text.length > MAX_BYTES && dropOldest(body)) {
    truncated = true;
    text = JSON.stringify(body);
  }
  return truncated;
}

/**
 * @param {any} body
 * @returns {boolean}
 */
function dropOldest(body) {
  const arp = body.scratch && body.scratch['arp-spoof'];
  const bindings = arp && arp.bindings && arp.bindings.map;
  if (Array.isArray(bindings) && bindings.length > 0) {
    bindings.shift();
    return true;
  }
  const identity = body.scratch && body.scratch['identity-change'];
  const macs = identity && identity.macs && identity.macs.map;
  if (Array.isArray(macs) && macs.length > 0) {
    macs.shift();
    return true;
  }
  return false;
}

/**
 * @param {any} device
 */
function progressOf(device) {
  /** @type {Record<string, unknown>} */
  const out = {
    mode: device.mode,
    frozen: device.frozen,
    seen: device.seen,
    learnStart: device.learnStart,
    windowsActive: device.windowsActive || 0,
    suspicious: device.suspicious ? device.suspicious.slice() : [],
    learningExtended: Boolean(device.learningExtended),
  };
  if (typeof device.lastTs === 'number') out.lastTs = device.lastTs;
  const horizon = exportHorizon(device);
  if (horizon) out.horizon = horizon;
  return out;
}

/**
 * JSON copy of live detector state. `exportState` drops open-window counters; this keeps them.
 * @param {Map<string, any>} states
 * @returns {Record<string, unknown>}
 */
function freezeStates(states) {
  /** @type {Record<string, unknown>} */
  const out = Object.create(null);
  for (const [id, state] of states) out[id] = plain(state);
  return out;
}

/**
 * @param {unknown} raw
 * @returns {Map<string, any>}
 */
function thawStates(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('checkpoint live state is invalid');
  }
  assertSafeKeys(raw, 'checkpoint live');
  const states = new Map();
  for (const [id, value] of Object.entries(raw)) states.set(id, revive(value));
  return states;
}

/**
 * A restored live state must keep the Sets, Maps, rings and nested objects
 * that `createState` built. A mutated tag otherwise revives as a plain object
 * and the next feed calls `.has` on it.
 * @param {any} fresh
 * @param {any} live
 * @returns {void}
 */
function assertLiveShape(fresh, live) {
  if (
    fresh instanceof LruSet ||
    fresh instanceof SampleRing ||
    fresh instanceof Map ||
    fresh instanceof Set
  ) {
    if (live == null || live.constructor !== fresh.constructor) {
      throw new Error('checkpoint live state is invalid');
    }
    return;
  }
  if (Array.isArray(fresh)) {
    if (!Array.isArray(live)) throw new Error('checkpoint live state is invalid');
    return;
  }
  if (fresh && typeof fresh === 'object') {
    if (!live || typeof live !== 'object' || Array.isArray(live)) {
      throw new Error('checkpoint live state is invalid');
    }
    for (const key of Object.keys(fresh)) {
      if (!Object.prototype.hasOwnProperty.call(live, key)) {
        throw new Error('checkpoint live state is invalid');
      }
      assertLiveShape(fresh[key], live[key]);
    }
  }
}

/**
 * @param {any} device
 * @param {any} progress
 */
function applyProgress(device, progress) {
  if (!progress || typeof progress !== 'object') return;
  if (progress.mode === 'learning' || progress.mode === 'watching') device.mode = progress.mode;
  if (typeof progress.frozen === 'boolean') device.frozen = progress.frozen;
  if (typeof progress.seen === 'boolean') device.seen = progress.seen;
  if (typeof progress.learnStart === 'number') device.learnStart = progress.learnStart;
  if (typeof progress.windowsActive === 'number') device.windowsActive = progress.windowsActive;
  if (Array.isArray(progress.suspicious)) device.suspicious = progress.suspicious.slice();
  if (typeof progress.learningExtended === 'boolean')
    device.learningExtended = progress.learningExtended;
  if (typeof progress.lastTs === 'number' && Number.isFinite(progress.lastTs)) {
    device.lastTs = progress.lastTs;
  }
  if (progress.horizon != null) importHorizon(device, progress.horizon);
}

module.exports = {
  plainScratch,
  assertCheckpoint,
  assertRevived,
  fit,
  progressOf,
  applyProgress,
  revive,
  freezeStates,
  thawStates,
  assertLiveShape,
};
