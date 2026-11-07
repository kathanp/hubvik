// @ts-nocheck
'use strict';

const { createHmac, timingSafeEqual } = require('node:crypto');
const { HubvikError } = require('../errors');
const { canonical } = require('./baseline');
const { FORBIDDEN_KEYS } = require('./constants');
const { domainFamily } = require('./net');
const { assertSafeKeys } = require('./validate');

const DAY = 24 * 60 * 60 * 1000;
const WEEK = 7 * DAY;
const PEER_GATEWAYS = 3;
const FIELDS = new Set(['families', 'resolvers', 'updates', 'beacons']);

/**
 * @param {any} engine
 */
function listCap(engine) {
  const opts = engine.opts || (engine.engines && engine.engines[0] && engine.engines[0].opts);
  const cap = opts ? opts.explainCap : null;
  return typeof cap === 'number' && cap >= 0 ? cap : 1000;
}

/**
 * @param {any} engine
 * @param {(owner: any) => void} visit
 */
function eachEngine(engine, visit) {
  if (engine.devices && typeof engine.devices.get === 'function') visit(engine);
  if (Array.isArray(engine.engines)) {
    for (const shard of engine.engines) visit(shard);
  }
}

/**
 * @param {any} engine
 */
function watermarkOf(engine) {
  let mark = 0;
  eachEngine(engine, (owner) => {
    if (typeof owner.watermark === 'number' && owner.watermark > mark) mark = owner.watermark;
  });
  return mark;
}

/**
 * @param {string | Buffer} key
 * @param {object} body
 */
function signBody(key, body) {
  const mac = createHmac('sha256', key).update(canonical(body)).digest('hex');
  return { ...body, sig: { alg: 'HMAC-SHA256', mac } };
}

/**
 * @param {string | Buffer} key
 * @param {any} row
 */
function signatureOk(key, row) {
  const mac = row && row.sig && row.sig.mac;
  if (typeof mac !== 'string' || !/^[0-9a-f]{64}$/i.test(mac)) return false;
  const expected = Buffer.from(
    createHmac('sha256', key).update(canonical(row)).digest('hex'),
    'hex',
  );
  const actual = Buffer.from(mac, 'hex');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * @param {unknown} key
 */
function requireKey(key) {
  if (typeof key !== 'string' && !Buffer.isBuffer(key)) {
    throw new HubvikError('SKETCH_KEY_IS_INVALID', 'sketch key is invalid');
  }
}

/**
 * @param {unknown} id
 */
function requireGateway(id) {
  if (typeof id !== 'string' || id.length === 0 || id.length > 255 || FORBIDDEN_KEYS.has(id)) {
    throw new HubvikError('GATEWAYID_IS_INVALID', 'gatewayId is invalid');
  }
}

/**
 * @param {unknown} name
 */
function goodName(name) {
  return (
    typeof name === 'string' && name.length > 0 && name.length <= 255 && !FORBIDDEN_KEYS.has(name)
  );
}

/**
 * @param {any} state
 * @param {string} key
 * @param {Set<string>} into
 */
function addStored(state, key, into) {
  if (!state || !state[key]) return;
  const value = state[key];
  const list = typeof value.toArray === 'function' ? value.toArray() : value;
  if (!Array.isArray(list) && typeof list[Symbol.iterator] !== 'function') return;
  for (const item of list) {
    if (goodName(item)) into.add(String(item));
  }
}

/**
 * @param {any} engine
 * @param {'families' | 'resolvers' | 'updates' | 'beacons'} field
 * @param {number} [bucketMs]
 */
function collect(engine, field, bucketMs) {
  /** @type {Set<string | number>} */
  const into = new Set();
  eachEngine(engine, (owner) => {
    if (!owner.devices) return;
    for (const device of owner.devices.values()) {
      const states = device.states;
      if (!states) continue;
      if (field === 'families') addStored(states.get('new-domain-family'), 'families', into);
      if (field === 'resolvers') addStored(states.get('resolver-bypass'), 'resolvers', into);
      if (field === 'updates') {
        const state = states.get('update-from-new-source');
        const seen = state && state.seen;
        const list = seen && typeof seen.toArray === 'function' ? seen.toArray() : [];
        for (const name of list) {
          const family = domainFamily(String(name));
          if (goodName(family)) into.add(family);
        }
      }
      if (field === 'beacons') {
        const state = states.get('new-beacon');
        const tracks = state && state.tracks;
        if (!tracks || typeof tracks.values !== 'function' || bucketMs == null) continue;
        for (const row of tracks.values()) {
          const gaps = row && row.gaps;
          const gap = Array.isArray(gaps) ? gaps[gaps.length - 1] : null;
          if (typeof gap === 'number' && gap >= 0) into.add(Math.floor(gap / bucketMs));
        }
      }
    }
  });
  return [...into].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)).slice(0, listCap(engine));
}

/**
 * @param {unknown} fields
 * @returns {string[]}
 */
function fieldsOf(fields) {
  if (!Array.isArray(fields) || fields.length === 0) {
    throw new HubvikError('SKETCH_FIELDS_ARE_INVALID', 'sketch fields are invalid');
  }
  /** @type {string[]} */
  const out = [];
  for (const field of fields) {
    if (typeof field !== 'string' || !FIELDS.has(field) || out.includes(field)) {
      throw new HubvikError('SKETCH_FIELDS_ARE_INVALID', 'sketch fields are invalid');
    }
    out.push(field);
  }
  return out;
}

/**
 * @param {unknown} value
 */
function bucketOf(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new HubvikError('SKETCH_BUCKET_IS_INVALID', 'sketch bucket is invalid');
  }
  return value;
}

/**
 * @param {unknown} value
 */
function capOf(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    throw new HubvikError('SKETCH_CAP_IS_INVALID', 'sketch cap is invalid');
  }
  return value;
}

/**
 * @param {any} engine
 */
function bookOf(engine) {
  if (!engine._sketches) engine._sketches = new Map();
  return engine._sketches;
}

/**
 * @param {string} gatewayId
 * @param {number} day
 */
function slot(gatewayId, day) {
  return `${gatewayId}\n${day}`;
}

/**
 * One signed sketch for the watermark's UTC day. Raw flows are not included.
 * @param {any} engine
 * @param {{ key: string | Buffer, gatewayId: string, fields: string[], bucketMs?: number }} opts
 */
function exportSketchOf(engine, opts = /** @type {any} */ ({})) {
  requireKey(opts.key);
  requireGateway(opts.gatewayId);
  const fields = fieldsOf(opts.fields);
  const bucketMs = fields.includes('beacons') ? bucketOf(opts.bucketMs) : null;
  const day = Math.floor(watermarkOf(engine) / DAY);
  /** @type {Record<string, unknown>} */
  const body = { v: 1, kind: 'day', gatewayId: opts.gatewayId, day };
  for (const field of fields) body[field] = collect(engine, /** @type {any} */ (field), bucketMs);
  const signed = signBody(opts.key, body);
  bookOf(engine).set(slot(opts.gatewayId, day), signed);
  engine._sketchGateway = opts.gatewayId;
  return signed;
}

/**
 * @param {any} row
 * @param {string | Buffer} key
 * @param {number} today
 */
function acceptDay(row, key, today) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) return null;
  try {
    assertSafeKeys(row, 'sketch');
  } catch {
    return null;
  }
  if (row.v !== 1 || row.kind !== 'day') return null;
  if (!signatureOk(key, row)) return null;
  if (typeof row.gatewayId !== 'string' || !goodName(row.gatewayId)) return null;
  if (typeof row.day !== 'number' || !Number.isInteger(row.day) || row.day < 0 || row.day > today) {
    return null;
  }
  if (today * DAY - row.day * DAY > WEEK) return null;
  for (const field of ['families', 'resolvers', 'updates']) {
    if (row[field] == null) continue;
    if (
      !Array.isArray(row[field]) ||
      row[field].some((/** @type {unknown} */ item) => !goodName(item))
    ) {
      return null;
    }
  }
  if (row.beacons != null) {
    if (
      !Array.isArray(row.beacons) ||
      row.beacons.some(
        (/** @type {unknown} */ item) =>
          typeof item !== 'number' || !Number.isInteger(item) || item < 0,
      )
    ) {
      return null;
    }
  }
  return row;
}

/**
 * Store peer sketches. A bad signature is skipped and the stored book is left as it was for that row.
 * @param {any} engine
 * @param {any[]} list
 * @param {{ verify: string | Buffer, cap: number }} opts
 */
function importSketchesOf(engine, list, opts = /** @type {any} */ ({})) {
  requireKey(opts.verify);
  const cap = capOf(opts.cap);
  if (!Array.isArray(list)) {
    throw new HubvikError('SKETCHES_MUST_BE_AN_ARRAY', 'sketches must be an array');
  }
  const today = Math.floor(watermarkOf(engine) / DAY);
  const next = new Map(bookOf(engine));
  for (const row of list) {
    const accepted = acceptDay(row, opts.verify, today);
    if (!accepted) continue;
    next.set(slot(accepted.gatewayId, accepted.day), accepted);
  }
  if (next.size > cap) {
    throw new HubvikError('ARRAY_SKETCHES_EXCEEDS_CAP', 'array sketches exceeds cap');
  }
  engine._sketches = next;
}

/**
 * Sign the update-host families the host already listed.
 * @param {any} engine
 * @param {{ key: string | Buffer, updates: string[] }} opts
 */
function exportAllowSketchOf(engine, opts = /** @type {any} */ ({})) {
  requireKey(opts.key);
  if (
    !Array.isArray(opts.updates) ||
    opts.updates.some((/** @type {unknown} */ name) => !goodName(name))
  ) {
    throw new HubvikError('ALLOW_UPDATES_ARE_INVALID', 'allow updates are invalid');
  }
  const updates = [...new Set(opts.updates)].sort().slice(0, listCap(engine));
  return signBody(opts.key, { v: 1, kind: 'allow', updates });
}

/**
 * A bad signature leaves the allow list unchanged.
 * @param {any} engine
 * @param {any} sketch
 * @param {{ verify: string | Buffer }} opts
 */
function importAllowSketchOf(engine, sketch, opts = /** @type {any} */ ({})) {
  requireKey(opts.verify);
  const previous = engine._allowUpdates || [];
  if (!sketch || typeof sketch !== 'object' || Array.isArray(sketch) || sketch.kind !== 'allow') {
    return { updates: previous.slice() };
  }
  try {
    assertSafeKeys(sketch, 'sketch');
  } catch {
    return { updates: previous.slice() };
  }
  if (sketch.v !== 1 || !signatureOk(opts.verify, sketch)) return { updates: previous.slice() };
  if (
    !Array.isArray(sketch.updates) ||
    sketch.updates.some((/** @type {unknown} */ name) => !goodName(name))
  ) {
    return { updates: previous.slice() };
  }
  engine._allowUpdates = [...new Set(sketch.updates.map(String))].sort();
  return { updates: engine._allowUpdates.slice() };
}

/**
 * @param {any} sketch
 * @param {string} field
 */
function namesOf(sketch, field) {
  const value = sketch && sketch[field];
  return Array.isArray(value) ? value : [];
}

/**
 * @param {any} engine
 * @param {{ on?: boolean }} [opts]
 */
function fleetOf(engine, opts = {}) {
  if (!opts || opts.on !== true) return { on: false, rows: [] };
  const book = bookOf(engine);
  const localId = engine._sketchGateway;
  const today = Math.floor(watermarkOf(engine) / DAY);
  const peers = [...book.values()].filter((/** @type {any} */ row) => {
    return row.gatewayId !== localId && today * DAY - row.day * DAY <= WEEK && row.day <= today;
  });
  const gateways = new Set(peers.map((/** @type {any} */ row) => row.gatewayId));
  if (gateways.size < PEER_GATEWAYS) return { on: true, rows: [] };
  const localToday = book.get(slot(localId, today));
  const localYesterday = book.get(slot(localId, today - 1));
  const peerToday = peers.filter((/** @type {any} */ row) => row.day === today);
  const peerYesterday = peers.filter((/** @type {any} */ row) => row.day === today - 1);
  const todayGateways = new Set(peerToday.map((/** @type {any} */ row) => row.gatewayId));
  if (todayGateways.size < PEER_GATEWAYS) return { on: true, rows: [] };
  const allowed = new Set(engine._allowUpdates || []);
  /** @type {any[]} */
  const rows = [];
  for (const field of ['families', 'updates']) {
    const localNow = new Set(namesOf(localToday, field));
    const localThen = new Set(namesOf(localYesterday, field));
    const seen = new Set([...localNow, ...localThen]);
    for (const row of peerToday) for (const name of namesOf(row, field)) seen.add(name);
    for (const row of peerYesterday) for (const name of namesOf(row, field)) seen.add(name);
    for (const name of [...seen].sort()) {
      if (field === 'updates' && allowed.has(name)) continue;
      const hereNow = localNow.has(name);
      const hereThen = localThen.has(name);
      const allToday = peerToday.every((/** @type {any} */ row) =>
        namesOf(row, field).includes(name),
      );
      const noneToday = peerToday.every(
        (/** @type {any} */ row) => !namesOf(row, field).includes(name),
      );
      const noneYesterday =
        peerYesterday.length > 0 &&
        peerYesterday.every((/** @type {any} */ row) => !namesOf(row, field).includes(name));
      if (hereNow && hereThen && noneToday) {
        rows.push({ kind: 'rare-here-rare-peers', field, name, day: today });
      }
      if (hereNow && !hereThen && allToday) {
        rows.push({ kind: 'new-here-common-peers', field, name, day: today });
      }
      if (allToday && noneYesterday) {
        rows.push({ kind: 'overlap-absent-yesterday', field, name, day: today });
      }
    }
  }
  return { on: true, rows };
}

const sketchMethods = {
  /**
   * @param {{ key: string | Buffer, gatewayId: string, fields: string[], bucketMs?: number }} opts
   */
  exportSketch(opts) {
    return exportSketchOf(this, opts);
  },
  /**
   * @param {any[]} list
   * @param {{ verify: string | Buffer, cap: number }} opts
   */
  importSketches(list, opts) {
    importSketchesOf(this, list, opts);
  },
  /**
   * @param {{ key: string | Buffer, updates: string[] }} opts
   */
  exportAllowSketch(opts) {
    return exportAllowSketchOf(this, opts);
  },
  /**
   * @param {any} sketch
   * @param {{ verify: string | Buffer }} opts
   */
  importAllowSketch(sketch, opts) {
    return importAllowSketchOf(this, sketch, opts);
  },
  /**
   * @param {{ on?: boolean }} [opts]
   */
  fleet(opts) {
    return fleetOf(this, opts);
  },
};

module.exports = { sketchMethods };
