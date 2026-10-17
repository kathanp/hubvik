'use strict';

const { assertSafeKeys } = require('./validate');

const MAX_BYTES = 16 * 1024 * 1024;
const KNOWN = new Set(['arp-spoof', 'identity-change', 'dhcp-starvation', 'fleet-wave']);

/**
 * @param {unknown} value
 * @returns {any}
 */
function plain(value) {
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
  const keys = Object.keys(value);
  if (keys.length === 1 && keys[0] === 'map' && Array.isArray(value.map)) {
    return new Map(value.map.map((/** @type {any[]} */ pair) => [pair[0], revive(pair[1])]));
  }
  if (keys.length === 1 && keys[0] === 'set' && Array.isArray(value.set)) {
    return new Set(value.set.map(revive));
  }
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
  return {
    mode: device.mode,
    frozen: device.frozen,
    seen: device.seen,
    learnStart: device.learnStart,
    windowsActive: device.windowsActive || 0,
    suspicious: device.suspicious ? device.suspicious.slice() : [],
    learningExtended: Boolean(device.learningExtended),
  };
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
}

module.exports = {
  plainScratch,
  assertCheckpoint,
  fit,
  progressOf,
  applyProgress,
  revive,
};
