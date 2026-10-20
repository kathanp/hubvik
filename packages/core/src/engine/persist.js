'use strict';

const { assertSafeKeys, validateEvent } = require('./validate');
const { readFeedback, noteNoisy } = require('./feedback');
const { prepareImport, attachMeta } = require('./baseline');
const { exportGraph, importGraph } = require('./graph');
const {
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
} = require('./checkpoint');
const pkg = require('../../package.json');

const PKG = `${pkg.name}@${pkg.version}`;

/**
 * Baselines, checkpoints, and restore.
 * Installed on Engine.prototype. Behavior is unchanged.
 */

module.exports = {
  /**
   * @this {any}
   * @param {{ devices?: string[], createdAt?: number, sign?: string | Buffer }} [opts]
   */
  exportBaseline(opts = {}) {
    const ids = opts.devices ? opts.devices.slice() : [...this.devices.keys()];
    ids.sort();
    /** @type {Record<string, object>} */
    const devices = Object.create(null);
    for (const id of ids) {
      const device = this.devices.get(id);
      if (!device) continue;
      /** @type {Record<string, { v: number, state: object }>} */
      const detectors = Object.create(null);
      for (const det of this.registry) {
        const stored = device.states.get(det.id);
        if (/** @type {any} */ (this)._shadowBlocked(det)) continue;
        if (!stored && det.defaults && det.defaults.enabled === false) continue;
        const state = stored ?? /** @type {any} */ (this)._freshState(det);
        const exported = typeof det.exportState === 'function' ? det.exportState(state) : {};
        detectors[det.id] = { v: det.version, state: exported };
      }
      /** @type {Record<string, unknown>} */
      const row = { peerGroup: device.peerGroup, detectors };
      if (device.deviceClass) row.deviceClass = device.deviceClass;
      devices[id] = row;
    }
    const body = {
      version: 3,
      createdAt: opts.createdAt ?? Date.now(),
      engine: { windowMs: this.opts.windowMs, pkg: PKG },
      devices,
    };
    return attachMeta(body, {
      sign: opts.sign,
      createdAt: body.createdAt,
      windowMs: this.opts.windowMs,
      pkg: PKG,
    });
  },

  /**
   * @this {any}
   * Reject live detector state whose exported form cannot be imported.
   * @param {unknown} live
   * @returns {void}
   */
  _probeLive(live) {
    const states = thawStates(live);
    for (const [id, state] of states) {
      const det = this.byId.get(id);
      if (!det || typeof det.exportState !== 'function' || typeof det.importState !== 'function') {
        throw new Error('checkpoint live state is invalid');
      }
      assertLiveShape(/** @type {any} */ (this)._freshState(det), state);
      det.importState(
        /** @type {any} */ (this)._freshState(det),
        det.exportState(state),
        /** @type {any} */ (this)._caps(),
      );
    }
  },

  /**
   * @this {any}
   * JSON-safe snapshot of the baseline, LAN scratch tables, watermark, and learning progress.
   * @param {{ devices?: string[], createdAt?: number, sign?: string | Buffer }} [opts]
   */
  checkpoint(opts = {}) {
    const baseline = /** @type {any} */ (
      this.exportBaseline({
        devices: opts.devices,
        createdAt: opts.createdAt ?? Date.now(),
      })
    );
    for (const [id, row] of Object.entries(baseline.devices)) {
      const device = this.devices.get(id);
      if (device) {
        row.progress = progressOf(device);
        row.live = freezeStates(device.states);
      }
    }
    const body = {
      version: baseline.version,
      createdAt: baseline.createdAt,
      engine: baseline.engine,
      devices: baseline.devices,
      watermark: this.watermark,
      scratch: plainScratch(this.scratch),
    };
    const graph = exportGraph(this);
    if (graph) /** @type {any} */ (body).graph = graph;
    if (this._reorder) {
      /** @type {any} */ (body).reorder = this._reorder.map((/** @type {any} */ row) => ({
        seq: row.seq,
        event: row.event,
      }));
    }
    if (this._feedback.length > 0) {
      /** @type {any} */ (body).feedback = this._feedback.map((/** @type {any} */ row) => ({
        ...row,
      }));
    }
    if (fit(body))
      /** @type {any} */ (this)._warn(
        'CHECKPOINT_TRUNCATED',
        'checkpoint dropped the oldest LAN rows',
      );
    return attachMeta(body, {
      sign: opts.sign,
      createdAt: body.createdAt,
      windowMs: this.opts.windowMs,
      pkg: PKG,
    });
  },

  /**
   * @this {any}
   * Replace engine state with a checkpoint. Validates fully before mutating.
   * @param {object} raw
   * @param {{ verify?: string | Buffer }} [opts]
   * @returns {void}
   */
  restore(raw, opts = {}) {
    const cp = /** @type {any} */ (raw);
    assertCheckpoint(cp);
    /** @type {Record<string, any>} */
    const revived = {};
    if (cp.scratch != null) {
      for (const key of Object.keys(cp.scratch)) {
        try {
          revived[key] = revive(cp.scratch[key]);
        } catch (err) {
          throw new Error(`checkpoint scratch ${key} is invalid`, { cause: err });
        }
      }
    }
    assertRevived(revived);
    const reorder = this._readReorder(cp.reorder);
    if (cp.devices && typeof cp.devices === 'object') {
      for (const row of Object.values(cp.devices)) {
        if (row && typeof row === 'object' && row.live) this._probeLive(row.live);
      }
    }
    this.importBaseline(cp, { merge: false, verify: opts.verify });
    importGraph(this, cp.graph);
    this.watermark = typeof cp.watermark === 'number' ? cp.watermark : null;
    this.lastEventTs = this.watermark;
    this.scratch = new Map(Object.entries(revived));
    const devices = cp.devices;
    if (devices && typeof devices === 'object') {
      for (const [id, row] of Object.entries(devices)) {
        const device = this.devices.get(id);
        if (device && row && typeof row === 'object') {
          applyProgress(device, row.progress);
          if (row.live) device.states = thawStates(row.live);
        }
      }
    }
    if (reorder) {
      this._reorder = reorder.rows;
      this._reorderSeq = reorder.seq;
    }
    this._feedback = readFeedback(cp.feedback);
    this._anomalyById = new Map();
    this._anomalyByFp = new Map();
    this._noisy = new Set();
    noteNoisy(this);
    this._rebuildReorderHigh();
  },

  /**
   * @this {any}
   * Validate a checkpoint reorder buffer without installing it.
   * @param {unknown} raw
   * @returns {{ rows: { seq: number, event: any }[], seq: number } | null}
   */
  _readReorder(raw) {
    if (raw == null) return null;
    if (!Array.isArray(raw)) throw new Error('checkpoint reorder buffer is invalid');
    if (raw.length > this.opts.maxBuffered) {
      throw new Error('checkpoint reorder buffer exceeds cap');
    }
    /** @type {{ seq: number, event: any }[]} */
    const rows = [];
    let seq = 0;
    let prevTs = -Infinity;
    let prevSeq = 0;
    for (const item of raw) {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        throw new Error('checkpoint reorder buffer is invalid');
      }
      assertSafeKeys(item, 'reorder');
      if (typeof item.seq !== 'number' || !Number.isInteger(item.seq) || item.seq < 1) {
        throw new Error('checkpoint reorder buffer is invalid');
      }
      if (!item.event || typeof item.event !== 'object' || Array.isArray(item.event)) {
        throw new Error('checkpoint reorder buffer is invalid');
      }
      const checked = validateEvent(item.event);
      if (checked.event.ts < prevTs || (checked.event.ts === prevTs && item.seq <= prevSeq)) {
        throw new Error('checkpoint reorder buffer is invalid');
      }
      prevTs = checked.event.ts;
      prevSeq = item.seq;
      rows.push({ seq: item.seq, event: item.event });
      if (item.seq > seq) seq = item.seq;
    }
    return { rows, seq };
  },

  /**
   * @this {any}
   * Highest accepted timestamp per device, from applied events and the buffer.
   * @returns {void}
   */
  _rebuildReorderHigh() {
    this._reorderHigh = new Map();
    for (const device of this.devices.values()) {
      if (typeof device.lastTs === 'number') this._reorderHigh.set(device.id, device.lastTs);
    }
    if (!this._reorder) return;
    for (const row of this._reorder) {
      const prev = this._reorderHigh.get(row.event.device);
      if (prev == null || row.event.ts > prev)
        this._reorderHigh.set(row.event.device, row.event.ts);
    }
  },

  /**
   * @this {any}
   * @param {object} raw
   * @param {{ merge?: boolean, verify?: string | Buffer }} [opts]
   * @returns {void}
   */
  importBaseline(raw, opts = {}) {
    const prepared = prepareImport(raw, {
      windowMs: this.opts.windowMs,
      registry: this.registry,
      caps: /** @type {any} */ (this)._caps(),
      verify: opts.verify,
    });
    if (opts.merge === false) this.devices.clear();
    for (const item of prepared) {
      let device = this.devices.get(item.id);
      if (!device) {
        if (this.devices.size >= this.opts.maxDevices) {
          /** @type {any} */ (this)._warn('STATE_CAP', 'device cap reached', item.id);
          this._stateCap(item.id, 0);
          continue;
        }
        device = /** @type {any} */ (this)._blank(item.id);
      }
      device.states = item.states;
      device.peerGroup = item.peerGroup;
      device.deviceClass = item.deviceClass;
      device.mode = 'watching';
      device.frozen = true;
      device.seen = true;
      device.learnStart = 0;
      device.open = null;
      device.cursor = null;
      this.devices.set(item.id, device);
    }
  },
};
