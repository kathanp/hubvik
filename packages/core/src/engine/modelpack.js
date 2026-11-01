'use strict';

const { HubvikError } = require('../errors');

const { CLASSES } = require('./classes');
const { FORBIDDEN_KEYS } = require('./constants');
const { prepareImport } = require('./baseline');
const { assertSafeKeys } = require('./validate');
const { domainFamily } = require('./net');

/**
 * Load a signed device-model pack. Default off. The package ships no pack file.
 * @this {any}
 * @param {any} pack
 * @param {{ verify?: string | Buffer }} [opts]
 * @returns {void}
 */
function loadModelPack(pack, opts = {}) {
  if (this.opts.modelPack !== true) {
    throw new HubvikError('MODEL_PACK_IS_OFF', 'model pack is off');
  }
  const blocks = readPack(this, pack, opts);
  const model = pack.model;
  if (!this._modelPacks) this._modelPacks = Object.create(null);
  this._modelPacks[model] = blocks;
  for (const device of this.devices.values()) {
    if (device.deviceClass !== model || device.states.size !== 0) continue;
    applyBlocks(this, device, blocks);
  }
}

/**
 * Seed an empty device when its class already has a pack.
 * @param {any} engine
 * @param {any} device
 * @returns {void}
 */
function applyStoredPack(engine, device) {
  if (engine.opts.modelPack !== true || !engine._modelPacks) return;
  const blocks = engine._modelPacks[device.deviceClass];
  if (!blocks || device.states.size !== 0) return;
  applyBlocks(engine, device, blocks);
}

/**
 * @param {any} engine
 * @param {any} pack
 * @param {{ verify?: string | Buffer }} opts
 * @returns {Record<string, any>}
 */
function readPack(engine, pack, opts) {
  if (!pack || typeof pack !== 'object' || Array.isArray(pack)) {
    throw new HubvikError('MODEL_PACK_IS_INVALID', 'model pack is invalid');
  }
  assertSafeKeys(pack, 'model pack');
  if (opts.verify == null) throw new HubvikError('MODEL_PACK_IS_INVALID', 'model pack is invalid');
  if (pack.version !== 3) throw new HubvikError('MODEL_PACK_IS_INVALID', 'model pack is invalid');
  if (typeof pack.model !== 'string' || pack.model.length === 0 || pack.model.length > 255) {
    throw new HubvikError('MODEL_PACK_IS_INVALID', 'model pack is invalid');
  }
  if (FORBIDDEN_KEYS.has(pack.model) || !CLASSES[pack.model]) {
    throw new HubvikError('MODEL_PACK_IS_INVALID', 'model pack is invalid');
  }
  prepareImport(pack, {
    windowMs: engine.opts.windowMs,
    registry: engine.registry,
    caps: engine._caps(),
    verify: opts.verify,
  });
  const record = pack.devices && pack.devices[pack.model];
  if (!record || !record.detectors || typeof record.detectors !== 'object') {
    throw new HubvikError('MODEL_PACK_IS_INVALID', 'model pack is invalid');
  }
  return record.detectors;
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {Record<string, any>} blocks
 * @returns {void}
 */
function applyBlocks(engine, device, blocks) {
  /** @type {string[]} */
  const families = [];
  for (const detId of Object.keys(blocks)) {
    const det = engine.byId.get(detId);
    if (!det) throw new HubvikError('UNKNOWN_DETECTOR', `unknown detector ${detId}`);
    const block = blocks[detId];
    const state = det.createState(engine._caps());
    det.importState(state, block.state, engine._caps());
    device.states.set(detId, state);
    if (detId === 'new-destination' && state.dsts && typeof state.dsts.toArray === 'function') {
      for (const dst of state.dsts.toArray()) {
        const family = domainFamily(dst);
        if (family) families.push(family);
      }
    }
  }
  reportPackPoison(engine, device, families);
}

/**
 * A pack destination that no other local peer has learned still reaches the shadow row.
 * @param {any} engine
 * @param {any} device
 * @param {string[]} families
 * @returns {void}
 */
function reportPackPoison(engine, device, families) {
  const det = engine.byId.get('fleet-baseline-poisoning');
  if (!det || engine._shadowBlocked(det) || families.length === 0) return;
  /** @type {Set<string>} */
  const local = new Set();
  let peers = 0;
  for (const other of engine.devices.values()) {
    if (other === device) continue;
    const state = other.states && other.states.get('peer-divergence');
    if (!state || !state.families || state.families.size === 0) continue;
    peers += 1;
    for (const family of state.families) local.add(family);
  }
  if (peers === 0) return;
  for (const family of families) {
    if (local.has(family)) continue;
    const ctx = engine._ctx(device, false, engine.watermark || 0);
    ctx.options = engine._optionsFor(det);
    const draft = det.check(engine._state(device, det), { ts: engine.watermark || 0, family }, ctx);
    engine._take(device, det, draft, false, null);
  }
}

module.exports = { loadModelPack, applyStoredPack };
