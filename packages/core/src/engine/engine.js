'use strict';

const { createHash } = require('node:crypto');
const { EventEmitter } = require('node:events');
const { ALL } = require('../detectors');
const { LruSet } = require('./caps');
const { validateEvent, validateOptions, validateIndicator } = require('./validate');
const { windowStart, planClose } = require('./window');
const { prepareImport, attachMeta } = require('./baseline');
const { buildStats } = require('./stats');
const { ALLOW_KINDS, EVENT_TYPES, EVENT_TYPE_SET, FORBIDDEN_KEYS } = require('./constants');
const { noteLearning, mark } = require('./learning');
const { buildIndex } = require('./indicators');
const { noteIncident, ackIncident } = require('./incidents');
const {
  plainScratch,
  assertCheckpoint,
  assertRevived,
  fit,
  progressOf,
  applyProgress,
  revive,
} = require('./checkpoint');
const { CLASSES } = require('./classes');
const ATTACK = require('../data/attack-map.json');
const pkg = require('../../package.json');

const PKG = `${pkg.name}@${pkg.version}`;
/** @type {Record<string, string[]>} */
const ROOT_KEYS = {
  'volume-spike': ['sigma', 'minBytes', 'peakFactor'],
  'fan-out': ['minFanout', 'fanoutFactor'],
  'new-destination': ['maxNewDstPerWindow'],
};

class Engine extends EventEmitter {
  /**
   * @param {object} [raw]
   */
  constructor(raw) {
    super();
    const opts = validateOptions(raw);
    this.opts = opts;
    this.registry = ALL.map((det) => det);
    /** @type {Map<string, any>} */
    this.byId = new Map(this.registry.map((det) => [det.id, det]));
    /** @type {Map<string, any>} */
    this.devices = new Map();
    /** @type {any[]} */
    this.indicators = [];
    this.acks = new LruSet(100_000);
    this.seq = 0;
    this.eventsIn = 0;
    this.anomalyCount = 0;
    this.warningCount = 0;
    this.allowCount = 0;
    this.suppressCount = 0;
    this._emittingWarning = false;
    this.startedAt = null;
    this.lastEventTs = null;
    this.watermark = null;
    this.inputGapAt = null;
    /** @type {Set<string>} */
    this.capAlerts = new Set();
    this.indicatorIndex = buildIndex([]);
    this.scratch = new Map();
    this.incidentSeq = 0;
    this._checkDetectorOptions(opts);
    this._rebuildActive();
  }

  /**
   * @param {any} opts
   */
  _checkDetectorOptions(opts) {
    for (const id of Object.keys(opts.detectors)) {
      if (!this.byId.has(id)) throw new TypeError(`unknown detector ${id}`);
    }
  }

  /** @returns {void} */
  _rebuildActive() {
    /** @type {any[]} */
    this.active = [];
    /** @type {Record<string, any[]>} */
    this.byType = Object.create(null);
    for (const type of EVENT_TYPES) this.byType[type] = [];
    /** @type {Record<string, { active: boolean, reason: string | null }>} */
    this.detectorStatus = Object.create(null);
    const enabled = new Set(this.opts.tiers);
    for (const det of this.registry) {
      const consumes = consumesOf(det);
      const over = this.opts.detectors[det.id];
      let status;
      if (over && over.enabled === false)
        status = { active: false, reason: 'disabled by configuration' };
      else {
        const missing = det.requires.filter((/** @type {string} */ tier) => !enabled.has(tier));
        status = missing.length
          ? { active: false, reason: `requires ${missing.join(',')}` }
          : { active: true, reason: null };
      }
      this.detectorStatus[det.id] = status;
      if (!status.active) continue;
      this.active.push(det);
      for (const type of consumes) this.byType[type].push(det);
    }
  }

  /** @returns {any} */
  _caps() {
    return this.opts;
  }

  /**
   * @param {any} det
   */
  _optionsFor(det) {
    const options = { ...det.defaults };
    const root = this.opts.raw;
    for (const key of ROOT_KEYS[det.id] ?? []) {
      if (this.opts.explicit.has(key)) options[key] = root[key];
    }
    const over = this.opts.detectors[det.id];
    if (over) {
      for (const [key, value] of Object.entries(over)) {
        if (key === 'enabled') continue;
        options[key] = value;
      }
    }
    return options;
  }

  /**
   * @param {string} id
   * @returns {any}
   */
  _blank(id) {
    return {
      id,
      mode: 'learning',
      frozen: false,
      seen: false,
      learnStart: null,
      lastTs: null,
      peerGroup: null,
      deviceClass: null,
      open: null,
      cursor: null,
      sealedUntil: null,
      states: new Map(),
      suppress: new Map(),
      allows: new Map(),
    };
  }

  /**
   * @param {any} det
   */
  _freshState(det) {
    return typeof det.createState === 'function' ? det.createState(this._caps()) : {};
  }

  /**
   * @param {any} device
   * @param {any} det
   */
  _state(device, det) {
    let state = device.states.get(det.id);
    if (!state) {
      state = this._freshState(det);
      device.states.set(det.id, state);
    }
    return state;
  }

  /**
   * @param {string} id
   */
  _requireDevice(id) {
    const device = this.devices.get(id);
    if (!device || !device.seen) throw new TypeError(`unknown device ${id}`);
    return device;
  }

  /**
   * Record one event. Synchronous. Listener failures become `warning` events.
   * @param {object} raw
   * @returns {void}
   */
  feed(raw) {
    const { event, warnings } = validateEvent(raw);
    if (event.type === 'flow') {
      if (!event.dst) event.dst = event.dstName || event.dstIp;
      if (event.bytes == null) event.bytes = (event.bytesOut || 0) + (event.bytesIn || 0);
    }
    this.eventsIn += 1;
    for (const warning of warnings) this._warn(warning.code, warning.message, event.device);
    if (this.startedAt == null) this.startedAt = event.ts;
    const device = this._touch(event.device, event.ts);
    if (!device) return;
    const reorder = this.opts.reorderMs;
    const start = windowStart(event.ts, this.opts.windowMs);
    const inOpen =
      device.open != null && event.ts >= device.open.start && event.ts < device.open.end;
    if (!inOpen && this._rejectedTime(device, event, reorder)) return;
    if (this.watermark == null || event.ts > this.watermark) this.watermark = event.ts;
    this.lastEventTs = this.watermark;
    device.lastTs = event.ts;
    this._advanceTo(device, start);
    this._note(device, event);
    if (event.tier) {
      if (!this.tierSeen) this.tierSeen = Object.create(null);
      this.tierSeen[event.tier] = event.ts;
    }
    if (device.mode === 'learning') {
      if (device.qualityWindow !== start) {
        device.qualityWindow = start;
        device.windowsActive = (device.windowsActive || 0) + 1;
      }
      noteLearning(this, device, event);
    }
    if (
      device.mode === 'learning' &&
      device.learnStart != null &&
      event.ts >= device.learnStart + this.opts.learnMs
    ) {
      const need = this.opts.minLearnWindows;
      if (need > 0 && (device.windowsActive || 0) < need) {
        if (!device.learningExtended) {
          device.learningExtended = true;
          this._warn(
            'LEARNING_EXTENDED',
            'still learning until enough active windows are seen',
            device.id,
            { ts: event.ts },
          );
        }
      } else this._enterWatch(device, event.ts);
    }
    this._run(device, event);
    this._tierNeverSeen(event.ts);
  }

  /**
   * Feed a batch after sorting it by timestamp. Does not mutate the input array.
   * @param {any[]} events
   * @returns {void}
   */
  feedBatch(events) {
    if (!Array.isArray(events)) throw new TypeError('events must be an array');
    const copy = events.slice().sort((a, b) => (a && a.ts ? a.ts : 0) - (b && b.ts ? b.ts : 0));
    for (const event of copy) this.feed(event);
  }

  /**
   * No argument drains every open window whose start is <= the watermark.
   * An explicit now closes only windows whose end is <= now.
   * @param {number} [now]
   * @returns {void}
   */
  flush(now) {
    const explicit = arguments.length > 0 && now !== undefined;
    if (explicit && (typeof now !== 'number' || !Number.isFinite(now))) {
      throw new TypeError('flush time is invalid');
    }
    if (!explicit) {
      this._drain();
      this.tick();
      return;
    }
    for (const device of this.devices.values()) {
      if (!device.seen) continue;
      const plan = planClose(
        device.cursor,
        device.open,
        now,
        this.opts.windowMs,
        this.opts.maxWindows,
      );
      this._applyPlan(device, plan);
    }
    this.tick(now);
  }

  /**
   * End-of-input: close the window that contains the watermark.
   * @returns {void}
   */
  _drain() {
    const at = this.watermark;
    if (typeof at !== 'number') return;
    for (const device of this.devices.values()) {
      if (!device.seen || !device.open || device.open.start > at) continue;
      const end = device.open.end;
      this._finalize(device, device.open);
      device.open = null;
      device.cursor = end;
      device.sealedUntil = end;
    }
  }

  /**
   * Drop a timestamp that would reopen a closed window.
   * A step inside the current open window is handled by the caller.
   * @param {any} device
   * @param {any} event
   * @param {number} reorder
   * @returns {boolean}
   */
  _rejectedTime(device, event, reorder) {
    const tooOld =
      (device.sealedUntil != null && event.ts < device.sealedUntil) ||
      (device.open != null && event.ts < device.open.start - reorder);
    if (!tooOld) return false;
    const behind = device.lastTs != null && event.ts < device.lastTs - reorder;
    if (behind) {
      this._warn('CLOCK_JUMP', 'timestamp moved backward', device.id);
      this._clockJump(device, event);
    }
    this._warn('LATE_EVENT', 'event is older than an open window', device.id);
    return true;
  }

  /**
   * Run time-based checks at now, or at the watermark when now is omitted.
   * @param {number} [now]
   * @returns {void}
   */
  tick(now) {
    const at = now === undefined ? this.watermark : now;
    if (at == null) return;
    if (typeof at !== 'number' || !Number.isFinite(at)) throw new TypeError('tick time is invalid');
    const det = this.byId.get('went-silent');
    const status = this.detectorStatus['went-silent'];
    if (det && status && status.active && typeof det.tick === 'function') {
      for (const device of this.devices.values()) {
        if (!device.seen || device.mode !== 'watching') continue;
        const ctx = this._ctx(device, false, at);
        ctx.options = this._optionsFor(det);
        this._take(device, det, det.tick(this._state(device, det), ctx), false, null);
      }
    }
    this._inputGap(at);
    this._tierSilent(at);
    this._tierNeverSeen(at);
  }

  /**
   * End learning for one device, or for every device.
   * @param {string} [deviceId]
   * @returns {void}
   */
  lock(deviceId) {
    const list = deviceId == null ? [...this.devices.values()] : [this._requireDevice(deviceId)];
    for (const device of list) {
      if (device.mode === 'learning' && device.seen) {
        if (!this._quality(device).ready) {
          this._warn('LOCKED_UNREVIEWED', 'locked before learning looked clean', device.id);
        }
        this._enterWatch(device, device.learnStart ?? 0);
      }
    }
  }

  /**
   * Clear detector baselines and learn again from the next event.
   * @param {string} deviceId
   * @param {{ detectors?: string[] }} [opts]
   * @returns {void}
   */
  relearn(deviceId, opts = {}) {
    const device = this._requireDevice(deviceId);
    const ids = opts.detectors ?? this.registry.map((det) => det.id);
    if (!Array.isArray(ids)) throw new TypeError('detectors must be an array');
    for (const id of ids) {
      const det = this.byId.get(id);
      if (!det) throw new TypeError(`unknown detector ${id}`);
      device.states.set(id, this._freshState(det));
    }
    device.mode = 'learning';
    device.frozen = false;
    device.learnStart = null;
    device.open = null;
    device.cursor = null;
    device.sealedUntil = null;
  }

  /**
   * Add a value to the frozen baseline.
   * @param {string} deviceId
   * @param {string} kind
   * @param {string} value
   * @returns {void}
   */
  allow(deviceId, kind, value) {
    if (!ALLOW_KINDS.includes(kind)) throw new TypeError('allow kind is invalid');
    if (typeof value !== 'string' || value.length === 0 || value.length > this.opts.maxString) {
      throw new TypeError('allow value is invalid');
    }
    const device = this._requireDevice(deviceId);
    let handled = false;
    for (const det of this.registry) {
      if (typeof det.allow !== 'function') continue;
      if (det.allow(this._state(device, det), kind, value)) handled = true;
    }
    if (!handled) {
      let set = device.allows.get(kind);
      if (!set) {
        set = new LruSet(this.opts.maxDestinations);
        device.allows.set(kind, set);
      }
      set.add(value);
    }
    this.allowCount += 1;
  }

  /**
   * Mute a detector for one device.
   * @param {string} deviceId
   * @param {string} detectorId
   * @param {{ untilTs?: number, match?: string }} [opts]
   * @returns {void}
   */
  suppress(deviceId, detectorId, opts = {}) {
    if (!this.byId.has(detectorId)) throw new TypeError(`unknown detector ${detectorId}`);
    const device = this._requireDevice(deviceId);
    /** @type {{ untilTs?: number, match?: string }} */
    const entry = {};
    if (opts.untilTs != null) {
      if (typeof opts.untilTs !== 'number' || !Number.isFinite(opts.untilTs)) {
        throw new TypeError('untilTs is invalid');
      }
      entry.untilTs = opts.untilTs;
    }
    if (opts.match != null) {
      if (typeof opts.match !== 'string') throw new TypeError('match is invalid');
      entry.match = opts.match;
    }
    let list = device.suppress.get(detectorId);
    if (!list) {
      list = [];
      device.suppress.set(detectorId, list);
    }
    if (list.length >= 64) list.shift();
    list.push(entry);
  }

  /**
   * Remember that an operator handled an anomaly.
   * @param {string} anomalyId
   * @returns {void}
   */
  ack(anomalyId) {
    if (typeof anomalyId !== 'string' || anomalyId.length === 0)
      throw new TypeError('anomaly id is invalid');
    this.acks.add(anomalyId);
    ackIncident(this, anomalyId);
  }

  /**
   * Tag a device with a shipped class prior. The tag applies before the first event.
   * @param {string} deviceId
   * @param {string} classId
   * @returns {void}
   */
  setDeviceClass(deviceId, classId) {
    if (typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)) {
      throw new TypeError('device id is invalid');
    }
    if (!CLASSES[classId]) throw new TypeError('unknown device class');
    let device = this.devices.get(deviceId);
    if (!device) {
      if (this.devices.size >= this.opts.maxDevices) {
        this._warn('STATE_CAP', 'device cap reached', deviceId);
        return;
      }
      device = this._blank(deviceId);
      this.devices.set(deviceId, device);
    }
    device.deviceClass = classId;
  }

  /**
   * Drop every byte of state for a device.
   * @param {string} deviceId
   * @returns {void}
   */
  forget(deviceId) {
    this.devices.delete(deviceId);
  }

  /**
   * @param {string} deviceId
   * @param {string | null} groupId
   * @returns {void}
   */
  setPeerGroup(deviceId, groupId) {
    if (typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)) {
      throw new TypeError('device id is invalid');
    }
    if (groupId != null && (typeof groupId !== 'string' || groupId.length > this.opts.maxString)) {
      throw new TypeError('peer group is invalid');
    }
    let device = this.devices.get(deviceId);
    if (!device) {
      if (this.devices.size >= this.opts.maxDevices) {
        this._warn('STATE_CAP', 'device cap reached', deviceId);
        return;
      }
      device = this._blank(deviceId);
      this.devices.set(deviceId, device);
    }
    device.peerGroup = groupId;
  }

  /**
   * Register a detector. Built-in ids cannot be replaced.
   * @param {any} detector
   * @returns {void}
   */
  use(detector) {
    this._assertDetector(detector);
    if (this.byId.has(detector.id))
      throw new TypeError(`detector ${detector.id} is already registered`);
    this.registry.push(detector);
    this.byId.set(detector.id, detector);
    this._rebuildActive();
  }

  /**
   * Replace the indicator set. The previous set is kept when validation fails.
   * @param {unknown[]} list
   * @returns {void}
   */
  loadIndicators(list) {
    if (!Array.isArray(list)) throw new TypeError('indicators must be an array');
    if (list.length > this.opts.maxIndicators) throw new Error('array indicators exceeds cap');
    const next = list.map((item) => validateIndicator(item));
    this.indicators = next;
    this.indicatorIndex = buildIndex(next);
  }

  /**
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
        const state = device.states.get(det.id) ?? this._freshState(det);
        const exported = typeof det.exportState === 'function' ? det.exportState(state) : {};
        detectors[det.id] = { v: det.version, state: exported };
      }
      /** @type {Record<string, unknown>} */
      const row = { peerGroup: device.peerGroup, detectors };
      if (device.deviceClass) row.deviceClass = device.deviceClass;
      devices[id] = row;
    }
    const body = {
      version: 2,
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
  }

  /**
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
      if (device) row.progress = progressOf(device);
    }
    const body = {
      version: baseline.version,
      createdAt: baseline.createdAt,
      engine: baseline.engine,
      devices: baseline.devices,
      watermark: this.watermark,
      scratch: plainScratch(this.scratch),
    };
    if (fit(body)) this._warn('CHECKPOINT_TRUNCATED', 'checkpoint dropped the oldest LAN rows');
    return attachMeta(body, {
      sign: opts.sign,
      createdAt: body.createdAt,
      windowMs: this.opts.windowMs,
      pkg: PKG,
    });
  }

  /**
   * Replace engine state with a checkpoint. Validates fully before mutating.
   * @param {object} raw
   * @param {{ verify?: string | Buffer }} [opts]
   * @returns {void}
   */
  restore(raw, opts = {}) {
    const cp = /** @type {any} */ (raw);
    assertCheckpoint(cp);
    const revived = revive(cp.scratch == null ? {} : cp.scratch);
    assertRevived(revived);
    this.importBaseline(cp, { merge: false, verify: opts.verify });
    this.watermark = typeof cp.watermark === 'number' ? cp.watermark : null;
    this.lastEventTs = this.watermark;
    this.scratch = new Map(Object.entries(revived));
    const devices = cp.devices;
    if (devices && typeof devices === 'object') {
      for (const [id, row] of Object.entries(devices)) {
        const device = this.devices.get(id);
        if (device && row && typeof row === 'object') applyProgress(device, row.progress);
      }
    }
  }

  /**
   * @param {object} raw
   * @param {{ merge?: boolean, verify?: string | Buffer }} [opts]
   * @returns {void}
   */
  importBaseline(raw, opts = {}) {
    const prepared = prepareImport(raw, {
      windowMs: this.opts.windowMs,
      registry: this.registry,
      caps: this._caps(),
      verify: opts.verify,
    });
    if (opts.merge === false) this.devices.clear();
    for (const item of prepared) {
      let device = this.devices.get(item.id);
      if (!device) {
        if (this.devices.size >= this.opts.maxDevices) {
          this._warn('STATE_CAP', 'device cap reached', item.id);
          this._stateCap(item.id, 0);
          continue;
        }
        device = this._blank(item.id);
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
  }

  /** @returns {object} */
  stats() {
    let memoryBytes = 256;
    for (const device of this.devices.values()) {
      memoryBytes += 256;
      for (const det of this.registry) {
        const state = device.states.get(det.id);
        if (state && typeof det.memoryEstimate === 'function')
          memoryBytes += det.memoryEstimate(state);
      }
    }
    return buildStats({
      events: this.eventsIn,
      anomalies: this.anomalyCount,
      warnings: this.warningCount,
      devices: [...this.devices.values()].filter((device) => device.seen).length,
      indicators: this.indicators.length,
      detectors: this.detectorStatus,
      memoryBytes,
      watermark: this.watermark,
      learningQuality: this._learningQuality(),
      allows: this.allowCount,
      suppresses: this.suppressCount,
      acks: this.acks.size,
    });
  }

  /**
   * @param {string} type
   * @param {...any} args
   * @returns {boolean}
   */
  emit(type, ...args) {
    const listeners = this.listeners(type).slice();
    for (const listener of listeners) {
      try {
        listener(...args);
      } catch (err) {
        if (type === 'warning' || this._emittingWarning) continue;
        const message = err instanceof Error ? err.message : String(err);
        this._warn('LISTENER_ERROR', message, args[0] && args[0].device);
      }
    }
    return listeners.length > 0;
  }

  /**
   * @param {string} id
   * @param {number} ts
   */
  _touch(id, ts) {
    let device = this.devices.get(id);
    if (!device) {
      if (this.devices.size >= this.opts.maxDevices) {
        this._warn('STATE_CAP', 'device cap reached', id);
        this._stateCap(id, ts);
        return null;
      }
      device = this._blank(id);
      this.devices.set(id, device);
    }
    if (!device.seen) {
      device.seen = true;
      device.mode = 'learning';
      device.frozen = false;
      device.learnStart = ts;
      this.emit('device-new', { device: id, ts, firstEvent: { ts } });
    } else if (device.learnStart == null && device.mode === 'learning') {
      device.learnStart = ts;
    }
    return device;
  }

  /**
   * @param {any} device
   * @param {number} start
   */
  _advanceTo(device, start) {
    if (device.open && start < device.open.end) return;
    if (!device.open && device.cursor == null) {
      device.open = this._window(start);
      device.cursor = start;
      return;
    }
    const plan = planClose(
      device.cursor,
      device.open,
      start,
      this.opts.windowMs,
      this.opts.maxWindows,
    );
    this._applyPlan(device, plan);
    device.open = this._window(start);
    device.cursor = start;
  }

  /**
   * @param {any} device
   * @param {{ closeOpen: boolean, idles: number[], cursor: number | null }} plan
   */
  _applyPlan(device, plan) {
    if (plan.closeOpen && device.open) this._finalize(device, device.open);
    for (const start of plan.idles) this._finalize(device, this._window(start));
    if (plan.closeOpen || plan.idles.length > 0) {
      device.open = null;
      device.cursor = plan.cursor;
    }
  }

  /**
   * @param {number} start
   */
  _window(start) {
    return {
      start,
      end: start + this.opts.windowMs,
      bytes: 0,
      dstCount: 0,
      dstSet: new Set(),
      saturated: false,
      fanoutAlerted: false,
      events: 0,
      newDst: 0,
      idle: false,
    };
  }

  /**
   * @param {any} device
   * @param {any} event
   */
  _note(device, event) {
    if (!device.open) return;
    device.open.events = (device.open.events || 0) + 1;
    device.open.bytes += event.bytes || 0;
    if (!event.dst) return;
    const win = device.open;
    if (win.dstSet.has(event.dst)) return;
    if (win.fanoutAlerted || win.dstSet.size >= this.opts.maxWindowDestinations) {
      win.dstCount += 1;
      win.saturated = true;
      return;
    }
    win.dstSet.add(event.dst);
    win.dstCount = win.dstSet.size;
  }

  /**
   * @param {any} device
   * @param {any} win
   */
  _finalize(device, win) {
    const learning =
      !device.frozen &&
      device.learnStart != null &&
      win.start < device.learnStart + this.opts.learnMs;
    const summary = {
      start: win.start,
      end: win.end,
      bytes: win.bytes,
      dstCount: win.dstCount,
      fanoutAlerted: win.fanoutAlerted,
      newDst: win.newDst,
      idle: win.bytes === 0 && win.dstCount === 0,
    };
    const ctx = this._ctx(device, learning, summary.start);
    ctx.window = summary;
    for (const det of this.active) {
      if (typeof det.onWindowClose !== 'function') continue;
      ctx.options = this._optionsFor(det);
      const draft = det.onWindowClose(this._state(device, det), summary, ctx);
      this._take(device, det, draft, learning, null);
    }
    win.dstSet = null;
  }

  /**
   * @param {any} device
   * @param {any} event
   */
  _run(device, event) {
    const learning = device.mode === 'learning';
    const ctx = this._ctx(device, learning, event.ts);
    ctx.window = device.open;
    const list = this.byType[event.type] || [];
    for (const det of list) {
      const state = this._state(device, det);
      ctx.options = this._optionsFor(det);
      if (learning && !det.hardRule) {
        if (typeof det.learn === 'function') {
          const noted = det.learn(state, event, ctx);
          if (noted && typeof noted.reason === 'string') {
            mark(this, device, event, noted.reason, noted.message || noted.reason);
          }
        }
      } else if (typeof det.check === 'function') {
        this._take(device, det, det.check(state, event, ctx), learning, event);
      }
    }
  }

  /**
   * @param {any} device
   * @param {boolean} learning
   * @param {number} ts
   * @returns {any}
   */
  _ctx(device, learning, ts) {
    const engine = this;
    return {
      learning,
      ts,
      deviceId: device.id,
      /** @param {number} value */
      hour(value) {
        return engine.opts.hourOf(value);
      },
      /** @param {number} value */
      day(value) {
        return engine.opts.dayOf(value);
      },
      options: null,
      window: null,
      extra: null,
      learnMs: engine.opts.learnMs,
      engineStarted: engine.startedAt,
      indicatorIndex: engine.indicatorIndex,
      policy: engine.opts.policy,
      deviceClass: CLASSES[device.deviceClass] || null,
      gatewayIp: engine.opts.gatewayIp,
      dhcpServers: engine.opts.dhcpServers,
      routers: engine.opts.routers,
      zones: engine.opts.zones,
      browserJa4: engine.opts.browserJa4,
      peerGroup: device.peerGroup,
      scratch: engine.scratch,
      peers() {
        const group = device.peerGroup;
        if (!group) return [];
        /** @type {any[]} */
        const list = [];
        for (const other of engine.devices.values()) {
          if (other !== device && other.peerGroup === group && other.seen) list.push(other);
        }
        return list;
      },
      /**
       * @param {any} other
       * @param {string} id
       */
      peerState(other, id) {
        return other && other.states ? other.states.get(id) : null;
      },
      /**
       * @param {string} ip
       */
      lookup(ip) {
        if (typeof engine.opts.lookup !== 'function') return null;
        const found = engine.opts.lookup(ip);
        if (!found || typeof found !== 'object') return null;
        return {
          asn: typeof found.asn === 'string' ? found.asn : null,
          country: typeof found.country === 'string' ? found.country : null,
        };
      },
      /** @param {any} det */
      detectorOptions(det) {
        return engine._optionsFor(det);
      },
    };
  }

  /**
   * @param {any} device
   * @param {number} ts
   */
  _enterWatch(device, ts) {
    if (device.mode === 'watching') return;
    device.mode = 'watching';
    device.frozen = true;
    this.emit('learned', { device: device.id, ts });
  }

  /**
   * @param {any} device
   * @param {any} det
   * @param {any} draft
   * @param {boolean} learning
   * @param {any} event
   */
  _take(device, det, draft, learning, event) {
    if (!draft) return;
    const list = Array.isArray(draft) ? draft : [draft];
    for (const item of list) {
      if (!item) continue;
      if (det.id !== 'alert-storm' && this._overStorm(device, item.ts)) continue;
      if (this._muted(device, det.id, item)) {
        this.suppressCount += 1;
        continue;
      }
      this.seq += 1;
      this.anomalyCount += 1;
      /** @type {Record<string, unknown>} */
      const anomaly = {
        id: String(this.seq),
        device: device.id,
        detector: det.id,
        category: item.category || det.category,
        severity: item.severity,
        confidence: clamp01(item.confidence),
        ts: item.ts,
        actual: String(item.actual),
        expected: String(item.expected),
        data: item.data ? { ...item.data } : {},
        hardRule: Boolean(learning),
        schema: 1,
        fingerprint: fingerprintOf(det.id, device.id, dedupKeyOf(item)),
      };
      if (det.meta && typeof det.meta.dedupGroup === 'string') {
        anomaly.dedupGroup = det.meta.dedupGroup;
      }
      if (this.opts.evidence !== false) {
        anomaly.evidence = evidenceOf(device, event, item);
      }
      if (item.attack) anomaly.attack = item.attack.slice();
      else if (/** @type {Record<string, string[]>} */ (ATTACK)[det.id]) {
        anomaly.attack = /** @type {Record<string, string[]>} */ (ATTACK)[det.id].slice();
      }
      noteIncident(this, device, anomaly);
      this.emit('anomaly', anomaly);
      if (
        learning &&
        (det.id === 'proxy-relay' || det.id === 'blockchain-c2' || det.id === 'class-violation')
      ) {
        this._special(
          'supply-chain-suspect',
          device,
          { ts: item.ts, device: device.id },
          { kind: 'supply', because: det.id },
          true,
        );
      }
      this._maybeDrift(device);
    }
  }

  /**
   * @param {any} device
   * @param {string} detectorId
   * @param {{ actual?: string, ts?: number }} draft
   */
  _muted(device, detectorId, draft) {
    const list = device.suppress.get(detectorId);
    if (!list) return false;
    for (const entry of list) {
      if (entry.untilTs != null && draft.ts != null && draft.ts > entry.untilTs) continue;
      if (entry.match != null && entry.match !== draft.actual) continue;
      return true;
    }
    return false;
  }

  /**
   * After a large download, several new behaviors are one incident with two explanations.
   * @param {any} device
   */
  _maybeDrift(device) {
    if (device.postDrift || !device.incident) return;
    const names = device.incident.detectors || [];
    if (!names.some((/** @type {string} */ name) => name.startsWith('update-'))) return;
    const others = names.filter(
      (/** @type {string} */ name) => !name.startsWith('update-') && name !== 'post-update-drift',
    );
    if (others.length < 3) return;
    device.postDrift = true;
    this._special(
      'post-update-drift',
      device,
      { ts: device.incident.lastTs, device: device.id },
      {
        kind: 'post-update-drift',
        others: others.length,
        updateId: names.find((/** @type {string} */ name) => name.startsWith('update-')),
      },
      false,
    );
  }

  /**
   * @param {any} device
   * @param {any} event
   */
  _clockJump(device, event) {
    this._special('clock-jump', device, event, { jump: 'backward' }, device.mode === 'learning');
  }

  /**
   * @param {string} id
   * @param {number} ts
   */
  _stateCap(id, ts) {
    if (this.capAlerts.has(id)) return;
    this.capAlerts.add(id);
    const device = this.devices.get(id) || { id, suppress: new Map(), states: new Map() };
    this._special(
      'state-cap',
      device,
      { ts, device: id },
      { kind: 'state-cap', cap: 'devices' },
      false,
    );
  }

  /**
   * @param {any} device
   */
  _quality(device) {
    const suspicious = device.suspicious ? device.suspicious.slice() : [];
    const windowsActive = device.windowsActive || 0;
    const families = device.learnFamilies ? device.learnFamilies.size : 0;
    return {
      windowsActive,
      families,
      suspicious,
      ready: suspicious.length === 0 && windowsActive >= this.opts.minLearnWindows,
    };
  }

  /**
   * @returns {Record<string, { windowsActive: number, families: number, suspicious: string[], ready: boolean }>}
   */
  _learningQuality() {
    /** @type {Record<string, any>} */
    const out = Object.create(null);
    for (const device of this.devices.values()) {
      if (!device.seen) continue;
      out[device.id] = this._quality(device);
    }
    return out;
  }

  /**
   * One warning per enabled tier that still has no events once learning has ended.
   * @param {number} now
   */
  _tierNeverSeen(now) {
    if (typeof now !== 'number' || this.startedAt == null) return;
    if (now < this.startedAt + this.opts.learnMs) return;
    if (!this.tierNeverWarned) this.tierNeverWarned = Object.create(null);
    const seen = this.tierSeen || {};
    for (const tier of this.opts.tiers) {
      if (typeof seen[tier] === 'number' || this.tierNeverWarned[tier]) continue;
      this.tierNeverWarned[tier] = true;
      this._warn('TIER_NEVER_SEEN', `${tier} had no events by the end of learning`, undefined, {
        ts: now,
      });
    }
  }

  /**
   * @param {number} now
   */
  _tierSilent(now) {
    const seen = this.tierSeen || {};
    const enabled = this.opts.tiers;
    const limitOf = (/** @type {string} */ tier) => {
      const table = this.opts.tierSilentByTier;
      if (table && typeof table[tier] === 'number') return table[tier];
      return this.opts.tierSilentMs;
    };
    const fresh = (/** @type {string} */ tier) => {
      const last = seen[tier];
      return typeof last === 'number' && now - last < this.opts.tierSilentMs;
    };
    const live = enabled.some(fresh);
    if (!live) return;
    if (!this.tierSilentFired) this.tierSilentFired = Object.create(null);
    for (const tier of enabled) {
      const last = seen[tier];
      if (typeof last !== 'number') continue;
      if (now - last < limitOf(tier)) continue;
      const key = String(last);
      if (this.tierSilentFired[tier] === key) continue;
      this.tierSilentFired[tier] = key;
      const detectors = this.registry
        .filter(
          (det) =>
            det.requires.includes(tier) &&
            this.detectorStatus[det.id] &&
            this.detectorStatus[det.id].active,
        )
        .map((det) => det.id);
      const device = { id: 'engine', suppress: new Map(), states: new Map() };
      this._special(
        'tier-silent',
        device,
        { ts: now, device: 'engine' },
        { kind: 'tier-silent', tier, detectors },
        false,
      );
    }
  }

  /**
   * @param {number} now
   */
  _inputGap(now) {
    if (this.lastEventTs == null) return;
    const gap = now - this.lastEventTs;
    const span = this.opts.maxWindows * this.opts.windowMs;
    if (gap < 24 * 3600e3 || gap > span) return;
    if (this.inputGapAt === this.lastEventTs) return;
    this.inputGapAt = this.lastEventTs;
    const device = { id: 'engine', suppress: new Map(), states: new Map() };
    this._special('input-gap', device, { ts: now, gapMs: gap }, { kind: 'input-gap' }, false);
  }

  /**
   * @param {any} device
   * @param {number} ts
   * @returns {boolean}
   */
  _overStorm(device, ts) {
    const det = this.byId.get('alert-storm');
    if (!det || !this.detectorStatus['alert-storm'] || !this.detectorStatus['alert-storm'].active) {
      return false;
    }
    const minute = Math.floor((ts || 0) / 60_000);
    if (device.stormMinute !== minute) {
      device.stormMinute = minute;
      device.stormCount = 0;
      device.stormSent = false;
    }
    device.stormCount += 1;
    const limit = this._optionsFor(det).maxPerMinute;
    if (device.stormCount <= limit) return false;
    if (!device.stormSent) {
      device.stormSent = true;
      this._special(
        'alert-storm',
        device,
        { ts, count: device.stormCount },
        { kind: 'alert-storm' },
        false,
      );
    }
    return true;
  }

  /**
   * @param {string} id
   * @param {any} device
   * @param {any} event
   * @param {any} extra
   * @param {boolean} learning
   */
  _special(id, device, event, extra, learning) {
    const det = this.byId.get(id);
    const status = this.detectorStatus[id];
    if (!det || !status || !status.active) return;
    const ctx = this._ctx(device, learning, event.ts || 0);
    ctx.extra = extra;
    ctx.options = this._optionsFor(det);
    const state = device.states ? this._state(device, det) : {};
    this._take(device, det, det.check(state, event, ctx), learning, event);
  }

  /**
   * @param {string} code
   * @param {string} message
   * @param {string} [device]
   * @param {{ reason?: string, ts?: number }} [extra]
   */
  _warn(code, message, device, extra) {
    this.warningCount += 1;
    if (this._emittingWarning) return;
    this._emittingWarning = true;
    try {
      /** @type {{ code: string, message: string, device?: string, reason?: string, ts?: number }} */
      const warning = { code, message };
      if (device) warning.device = device;
      if (extra && extra.reason) warning.reason = extra.reason;
      if (extra && typeof extra.ts === 'number') warning.ts = extra.ts;
      this.emit('warning', warning);
    } finally {
      this._emittingWarning = false;
    }
  }

  /**
   * @param {any} detector
   */
  _assertDetector(detector) {
    if (!detector || typeof detector !== 'object')
      throw new TypeError('detector must be an object');
    if (typeof detector.id !== 'string' || !/^[a-z0-9-]+$/.test(detector.id)) {
      throw new TypeError('detector.id is invalid');
    }
    if (!Number.isInteger(detector.version) || detector.version < 1) {
      throw new TypeError('detector.version is invalid');
    }
    if (!Array.isArray(detector.requires) || detector.requires.length === 0) {
      throw new TypeError('detector.requires is invalid');
    }
    if (!detector.defaults || typeof detector.defaults !== 'object') {
      throw new TypeError('detector.defaults is invalid');
    }
  }
}

/**
 * Event types `feed()` may pass to this detector. Missing `consumes` means every type.
 * An empty array means window close and engine signals only.
 * @param {any} det
 * @returns {string[]}
 */
function consumesOf(det) {
  const raw = det.meta && det.meta.consumes;
  if (raw == null) return EVENT_TYPES;
  if (!Array.isArray(raw)) throw new TypeError(`${det.id} consumes must be an array`);
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const type of raw) {
    if (typeof type !== 'string' || !EVENT_TYPE_SET.has(type)) {
      throw new TypeError(`${det.id} consumes unknown event type`);
    }
    if (seen.has(type)) continue;
    seen.add(type);
    out.push(type);
  }
  return out;
}

/**
 * Stable id for one fact. Same detector, device, and dedup key hash the same after a restart.
 * @param {string} detector
 * @param {string} device
 * @param {string} key
 * @returns {string}
 */
function fingerprintOf(detector, device, key) {
  return createHash('sha256').update(`${detector}\0${device}\0${key}`).digest('hex').slice(0, 16);
}

const MAGNITUDE = new Set([
  'hosts',
  'count',
  'bytes',
  'limit',
  'pkts',
  'gapMs',
  'maxGap',
  'ratio',
  'score',
  'bytesPerPacket',
]);

/**
 * A detector may set `dedupKey`. Otherwise the key is the non-magnitude fields of `data`.
 * Display text in `actual` is not part of the hash.
 * @param {{ dedupKey?: string, data?: Record<string, unknown> }} item
 * @returns {string}
 */
function dedupKeyOf(item) {
  if (typeof item.dedupKey === 'string' && item.dedupKey.length > 0) return item.dedupKey;
  const data = item.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return '';
  /** @type {string[]} */
  const parts = [];
  for (const key of Object.keys(data).sort()) {
    if (MAGNITUDE.has(key)) continue;
    const value = data[key];
    if (value == null || typeof value === 'object') continue;
    parts.push(`${key}=${String(value)}`);
  }
  return parts.join('\0');
}

/**
 * @param {any} device
 * @param {any} event
 * @param {any} item
 */
function evidenceOf(device, event, item) {
  /** @type {{ events: number, sample: object[], window?: { start: number, end: number }, baseline?: string }} */
  const evidence = {
    events: event ? 1 : device.open && device.open.events ? device.open.events : 0,
    sample: event ? [clipSample(event)] : [],
  };
  if (device.open) evidence.window = { start: device.open.start, end: device.open.end };
  if (typeof item.baseline === 'string') evidence.baseline = item.baseline;
  return evidence;
}

/**
 * Copy a normalized event without the engine-stamped tier, and keep it under 1 KB.
 * @param {any} event
 * @returns {object}
 */
function clipSample(event) {
  /** @type {Record<string, unknown>} */
  let copy;
  try {
    copy = JSON.parse(JSON.stringify(event));
  } catch {
    return {};
  }
  delete copy.tier;
  const keys = Object.keys(copy);
  while (keys.length > 0 && JSON.stringify(copy).length > 1024) {
    const key = keys.pop();
    if (key !== undefined) delete copy[key];
  }
  return copy;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function clamp01(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 1;
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

/**
 * @param {object} [opts]
 * @returns {Engine}
 */
function createEngine(opts) {
  return new Engine(opts);
}

module.exports = { createEngine, Engine };
