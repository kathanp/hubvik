'use strict';

const { EventEmitter } = require('node:events');
const { ALL } = require('../detectors');
const { LruSet } = require('./caps');
const { assertSafeKeys, validateEvent, validateOptions, validateIndicator } = require('./validate');
const { resolveIp } = require('./identity');
const { recordFeedback, labelsOf, precisionOf, noteNoisy, readFeedback } = require('./feedback');
const { prepareImport, attachMeta } = require('./baseline');
const { buildStats } = require('./stats');
const { ALLOW_KINDS, EVENT_TYPES, EVENT_TYPE_SET, FORBIDDEN_KEYS } = require('./constants');
const { horizonOn, horizonView } = require('./horizon');
const { graphOn, snapshot, exportGraph, importGraph } = require('./graph');
const { compileRules } = require('./rules');
const { buildIndex } = require('./indicators');
const { ackIncident } = require('./incidents');
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
const { CLASSES } = require('./classes');
const pkg = require('../../package.json');

const PKG = `${pkg.name}@${pkg.version}`;
const stateMethods = require('./state');
const windowMethods = require('./windows');
const feedMethods = require('./feed');
const emitMethods = require('./emit');
const { learningMethods } = require('./learning');

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
    this._rekeyed = 0;
    this._unresolved = 0;
    this._emittingWarning = false;
    /** @type {number | null} */
    this.startedAt = null;
    this.lastEventTs = null;
    this.watermark = null;
    this.inputGapAt = null;
    /** @type {Set<string>} */
    this.capAlerts = new Set();
    this.indicatorIndex = buildIndex([]);
    this.scratch = new Map();
    /** @type {Map<string, string>} Canonical copy of a repeated destination name. */
    this.names = new Map();
    this.incidentSeq = 0;
    this._checkDetectorOptions(opts);
    this._checkShadowList();
    let canaries = 0;
    for (const value of Object.values(opts.detectors)) {
      if (value && value.canary != null) canaries += 1;
    }
    if (canaries > 4) throw new Error('at most 4 canaries');
    /** @type {Record<string, { fired: number, devices: Set<string>, bySeverity: Record<string, number>, wouldJoinIncident: number }>} */
    this._shadow = Object.create(null);
    /** @type {Record<string, { liveOnly: number, canaryOnly: number, both: number }>} */
    this._canary = Object.create(null);
    this._promotionsNoted = false;
    this.shadowSeq = 0;
    /** @type {{ seq: number, event: any }[] | null} */
    this._reorder = opts.reorderMs > 0 ? [] : null;
    /** @type {Map<string, number>} */
    this._reorderHigh = new Map();
    this._reorderSeq = 0;
    /** @type {number | null} */
    this._reorderOverflowMinute = null;
    /** @type {Map<string, any>} */
    this._explain = new Map();
    /** @type {any[]} */
    this._feedback = [];
    /** @type {Map<string, any>} */
    this._anomalyById = new Map();
    /** @type {Map<string, any>} */
    this._anomalyByFp = new Map();
    /** @type {Set<string>} */
    this._noisy = new Set();
    /** @type {Set<string>} */
    this._bridges = new Set();
    /** @type {any[]} */
    this._pendingLinks = [];
    /** @type {any[]} */
    this._campaigns = [];
    this._campaignSeq = 0;
    /** @type {any[]} */
    this._rules = [];
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
  _checkShadowList() {
    const shadow = this.opts.shadow;
    if (!Array.isArray(shadow)) return;
    for (const id of shadow) {
      if (id.startsWith('rule:')) continue;
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
      const turnedOff =
        (over && over.enabled === false) ||
        /** @type {any} */ (this)._shadowBlocked(det) ||
        ((!over || over.enabled == null) && det.defaults && det.defaults.enabled === false);
      if (turnedOff) status = { active: false, reason: 'disabled by configuration' };
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
    this._horizonOn = horizonOn(this);
    this._graphOn = graphOn(this);
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
    const device = /** @type {any} */ (this)._requireDevice(deviceId);
    let handled = false;
    for (const det of this.registry) {
      if (typeof det.allow !== 'function') continue;
      if (det.allow(/** @type {any} */ (this)._state(device, det), kind, value)) handled = true;
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
    const device = /** @type {any} */ (this)._requireDevice(deviceId);
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
        /** @type {any} */ (this)._warn('STATE_CAP', 'device cap reached', deviceId);
        return;
      }
      device = /** @type {any} */ (this)._blank(deviceId);
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
        /** @type {any} */ (this)._warn('STATE_CAP', 'device cap reached', deviceId);
        return;
      }
      device = /** @type {any} */ (this)._blank(deviceId);
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
   * Replace the rule set. The previous set is kept when validation fails.
   * @param {unknown} rules
   * @returns {void}
   */
  loadRules(rules) {
    const compiled = compileRules(rules, this.opts.windowMs);
    this._rules = compiled;
    this.registry = ALL.map((det) => det).concat(compiled);
    this.byId = new Map(this.registry.map((det) => [det.id, det]));
    this._rebuildActive();
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
  }

  /**
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
      /** @type {any} */ (body).reorder = this._reorder.map((row) => ({
        seq: row.seq,
        event: row.event,
      }));
    }
    if (this._feedback.length > 0) {
      /** @type {any} */ (body).feedback = this._feedback.map((row) => ({ ...row }));
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
  }

  /**
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
  }

  /**
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
  }

  /**
   * The MAC bound to an address, or null.
   * @param {string} ip
   * @returns {string | null}
   */
  resolve(ip) {
    return resolveIp(this, ip);
  }

  /**
   * LAN edges, and WAN families when `includeWan` is set.
   * @param {{ device?: string, includeWan?: boolean }} [opts]
   */
  graph(opts) {
    return snapshot(this, opts || {});
  }

  stats() {
    let memoryBytes = 256;
    for (const device of this.devices.values()) {
      memoryBytes += 256;
      for (const det of this.registry) {
        const state = device.states.get(det.id);
        if (state && typeof det.memoryEstimate === 'function')
          memoryBytes += det.memoryEstimate(state);
        const copy = device.canary && device.canary.get(det.id);
        if (copy && typeof det.memoryEstimate === 'function')
          memoryBytes += det.memoryEstimate(copy);
      }
    }
    /** @type {Record<string, { fired: number, devices: number, bySeverity: Record<string, number>, wouldJoinIncident: number }>} */
    const shadow = Object.create(null);
    for (const [id, row] of Object.entries(this._shadow)) {
      shadow[id] = {
        fired: row.fired,
        devices: row.devices.size,
        bySeverity: { ...row.bySeverity },
        wouldJoinIncident: row.wouldJoinIncident,
      };
    }
    /** @type {Record<string, { liveOnly: number, canaryOnly: number, both: number }>} */
    const canary = Object.create(null);
    for (const [id, row] of Object.entries(this._canary)) canary[id] = { ...row };
    return buildStats({
      events: this.eventsIn,
      anomalies: this.anomalyCount,
      warnings: this.warningCount,
      devices: [...this.devices.values()].filter((device) => device.seen).length,
      indicators: this.indicators.length,
      detectors: this.detectorStatus,
      memoryBytes,
      watermark: this.watermark,
      learningQuality: /** @type {any} */ (this)._learningQuality(),
      allows: this.allowCount,
      suppresses: this.suppressCount,
      acks: this.acks.size,
      shadow,
      canary,
      identity: {
        rows: this.scratch.get('identity') instanceof Map ? this.scratch.get('identity').size : 0,
        rekeyed: this._rekeyed || 0,
        unresolved: this._unresolved || 0,
      },
      precision: precisionOf(this),
    });
  }

  /**
   * Record an operator verdict for an anomaly id or fingerprint.
   * @param {string} key
   * @param {'tp' | 'fp' | 'benign-true' | 'unknown'} verdict
   * @param {{ operator?: string, note?: string }} [opts]
   * @returns {void}
   */
  feedback(key, verdict, opts) {
    recordFeedback(this, key, verdict, opts);
  }

  /**
   * JSONL of the feedback ring. One object per line.
   * @returns {string}
   */
  exportLabels() {
    return labelsOf(this);
  }

  /**
   * @param {string} id
   * @param {number} ts
   */
  _touch(id, ts) {
    let device = this.devices.get(id);
    if (!device) {
      if (this.devices.size >= this.opts.maxDevices) {
        /** @type {any} */ (this)._warn('STATE_CAP', 'device cap reached', id);
        this._stateCap(id, ts);
        return null;
      }
      device = /** @type {any} */ (this)._blank(id);
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
   * @param {boolean} learning
   * @param {number} ts
   * @returns {any}
   */
  _ctx(device, learning, ts) {
    const engine = /** @type {any} */ (this);
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
      ownBssids: engine.opts.ownBssids,
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
      /**
       * Hourly ring for the device this context belongs to.
       * Callers may pass the detector state; it is not read.
       */
      horizon() {
        return horizonView(device);
      },
      lanEdges: device.lanEdges || null,
      bridges: engine._bridges || (engine._bridges = new Set()),
    };
  }

  /**
   * @param {any} device
   * @param {any} event
   */
  _clockJump(device, event) {
    /** @type {any} */ (this)._special(
      'clock-jump',
      device,
      event,
      { jump: 'backward' },
      device.mode === 'learning',
    );
  }

  /**
   * @param {string} id
   * @param {number} ts
   */
  _stateCap(id, ts) {
    if (this.capAlerts.has(id)) return;
    this.capAlerts.add(id);
    const device = this.devices.get(id) || { id, suppress: new Map(), states: new Map() };
    /** @type {any} */ (this)._special(
      'state-cap',
      device,
      { ts, device: id },
      { kind: 'state-cap', cap: 'devices' },
      false,
    );
  }

  /**
   * @param {any} detector
   */
  _assertDetector(detector) {
    if (!detector || typeof detector !== 'object')
      throw new TypeError('detector must be an object');
    if (typeof detector.id !== 'string' || !/^(?:rule:)?[a-z0-9-]+$/.test(detector.id)) {
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
 * @param {object} [opts]
 * @returns {Engine}
 */
function createEngine(opts) {
  return new Engine(opts);
}

Object.assign(
  Engine.prototype,
  stateMethods,
  windowMethods,
  feedMethods,
  learningMethods,
  emitMethods,
);

module.exports = { createEngine, Engine };
