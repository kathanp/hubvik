'use strict';

const { createHmac, timingSafeEqual } = require('node:crypto');
const { assertSafeKeys } = require('./validate');
const { CLASSES } = require('./classes');
const { FORBIDDEN_KEYS } = require('./constants');

/**
 * @param {unknown} value
 * @returns {string}
 */
function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(',')}]`;
  const record = /** @type {Record<string, unknown>} */ (value);
  const keys = Object.keys(record)
    .filter((key) => key !== 'sig')
    .sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(',')}}`;
}

/**
 * @param {object} body
 * @param {string | Buffer} key
 */
function signBody(body, key) {
  const mac = createHmac('sha256', key).update(canonical(body)).digest('hex');
  return { ...body, sig: { alg: 'HMAC-SHA256', mac } };
}

/**
 * @param {any} raw
 * @param {string | Buffer | undefined} key
 */
function assertSignature(raw, key) {
  if (key == null) return;
  const mac = raw && raw.sig && raw.sig.mac;
  if (
    !raw ||
    !raw.sig ||
    raw.sig.alg !== 'HMAC-SHA256' ||
    typeof mac !== 'string' ||
    !/^[0-9a-f]{64}$/i.test(mac)
  ) {
    throw new Error('baseline signature mismatch');
  }
  const expected = createHmac('sha256', key).update(canonical(raw)).digest('hex');
  const left = Buffer.from(expected, 'hex');
  const right = Buffer.from(mac, 'hex');
  if (left.length !== right.length || !timingSafeEqual(left, right)) {
    throw new Error('baseline signature mismatch');
  }
}

/**
 * @param {object} body
 * @param {{ createdAt: number, windowMs: number, pkg: string, sign?: string | Buffer }} meta
 */
function attachMeta(body, meta) {
  const signed = meta.sign == null ? body : signBody(body, meta.sign);
  return signed;
}

/**
 * Validate a whole baseline before any engine state changes.
 * @param {any} raw
 * @param {{ windowMs: number, registry: any[], caps: any, verify?: string | Buffer }} ctx
 * @returns {{ id: string, peerGroup: string | null, deviceClass: string | null, states: Map<string, object> }[]}
 */
function prepareImport(raw, ctx) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new Error('unsupported baseline');
  assertSafeKeys(raw, 'baseline');
  const modern = raw.version === 2 || raw.version === 3;
  if (raw.version !== 1 && !modern) throw new Error('unsupported baseline');
  assertSignature(raw, ctx.verify);
  if (modern) {
    if (!raw.engine || raw.engine.windowMs !== ctx.windowMs) throw new Error('windowMs mismatch');
  }
  if (!raw.devices || typeof raw.devices !== 'object' || Array.isArray(raw.devices)) {
    throw new Error('baseline devices are invalid');
  }
  assertSafeKeys(raw.devices, 'devices');
  const byId = new Map(ctx.registry.map((det) => [det.id, det]));
  /** @type {{ id: string, peerGroup: string | null, deviceClass: string | null, states: Map<string, object> }[]} */
  const prepared = [];
  for (const id of Object.keys(raw.devices)) {
    if (FORBIDDEN_KEYS.has(id) || id.length === 0 || id.length > ctx.caps.maxString) {
      throw new Error('string too long');
    }
    const record = raw.devices[id];
    if (!record || typeof record !== 'object' || Array.isArray(record)) {
      throw new Error('baseline device is invalid');
    }
    assertSafeKeys(record, id);
    const blocks = raw.version === 1 ? upgradeV1(record) : record.detectors;
    if (!blocks || typeof blocks !== 'object' || Array.isArray(blocks)) {
      throw new Error('baseline detectors are invalid');
    }
    assertSafeKeys(blocks, `${id}.detectors`);
    /** @type {Map<string, object>} */
    const states = new Map();
    for (const detId of Object.keys(blocks)) {
      const det = byId.get(detId);
      if (!det) throw new Error(`unknown detector ${detId}`);
      const block = blocks[detId];
      if (!block || typeof block !== 'object' || block.v !== det.version) {
        throw new Error(`detector state version mismatch for ${detId}`);
      }
      assertSafeKeys(block, detId);
      const dev = det.createState(ctx.caps);
      det.importState(dev, block.state, ctx.caps);
      states.set(detId, dev);
    }
    let peerGroup = null;
    if (modern && record.peerGroup != null) {
      if (typeof record.peerGroup !== 'string' || record.peerGroup.length > ctx.caps.maxString) {
        throw new Error('string too long');
      }
      peerGroup = record.peerGroup;
    }
    let deviceClass = null;
    if (modern && record.deviceClass != null) {
      if (typeof record.deviceClass !== 'string' || !CLASSES[record.deviceClass]) {
        throw new Error('device class is invalid');
      }
      deviceClass = record.deviceClass;
    }
    prepared.push({ id, peerGroup, deviceClass, states });
  }
  return prepared;
}

/**
 * Prototype version-1 device record becomes version-2 detector blocks.
 * @param {any} record
 */
function upgradeV1(record) {
  return {
    'new-destination': { v: 1, state: { dsts: record.dsts ?? [], alerted: [] } },
    'fan-out': { v: 1, state: { samples: record.winFanout ?? [] } },
    'volume-spike': { v: 1, state: { samples: record.winBytes ?? [] } },
    'wrong-time': { v: 1, state: { hours: record.hours ?? [], seen: [] } },
  };
}

module.exports = { canonical, attachMeta, prepareImport };
