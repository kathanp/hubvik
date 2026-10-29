'use strict';

const { HubvikError } = require('../errors');

const { EventEmitter } = require('node:events');
const { ALL } = require('../detectors');
const { LruSet } = require('./caps');
const { validateOptions, validateIndicator } = require('./validate');
const { resolveIp } = require('./identity');
const { recordFeedback, labelsOf, precisionOf } = require('./feedback');
const { buildStats } = require('./stats');
const { ALLOW_KINDS, EVENT_TYPES, EVENT_TYPE_SET, FORBIDDEN_KEYS } = require('./constants');
const { horizonOn, horizonView } = require('./horizon');
const { graphOn, snapshot } = require('./graph');
const { compileRules } = require('./rules');
const { buildIndex } = require('./indicators');
const { ackIncident } = require('./incidents');
const { CLASSES } = require('./classes');
const stateMethods = require('./state');
const windowMethods = require('./windows');
const feedMethods = require('./feed');
const emitMethods = require('./emit');
const persistMethods = require('./persist');
const { learningMethods } = require('./learning');
const { methods: finishMethods, createShardedEngine: sharded, zonedClock } = require('./finish09');
const { partgMethods } = require('./partg');
const { reportMethods } = require('./report');

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
    /** @type {number | null} */
    this.lastEventTs = null;
    /** @type {number | null} */
    this.watermark = null;
    this.inputGapAt = null;
    /** @type {Set<string>} */
    this.capAlerts = new Set();
    /** @type {string[]} */
    this._removedSince = [];
    this.indicatorIndex = buildIndex([]);
    this.scratch = new Map();
    /** @type {Map<string, string>} Canonical copy of a repeated destination name. */
    this.names = new Map();
    this.incidentSeq = 0;
    this._checkDetectorOptions(opts);
    this._checkShadowList();
    let canaries = 0;
    this._anyCanary = false;
    for (const value of Object.values(opts.detectors)) {
      if (value && value.canary != null) {
        canaries += 1;
        this._anyCanary = true;
      }
    }
    if (canaries > 4) throw new HubvikError('AT_MOST_4_CANARIES', 'at most 4 canaries');
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
    /** @type {any[]} Live anomalies kept for digest() and exportDecisions(). Capped by explainCap. */
    this._reports = [];
    /** @type {any[]} Shadow anomalies kept for shadow(). Capped by explainCap. Not checkpointed. */
    this._shadowReports = [];
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
      if (!this.byId.has(id)) throw new HubvikError('UNKNOWN_DETECTOR', `unknown detector ${id}`);
    }
  }

  /** @returns {void} */
  _checkShadowList() {
    const shadow = this.opts.shadow;
    if (!Array.isArray(shadow)) return;
    for (const id of shadow) {
      if (id.startsWith('rule:')) continue;
      if (!this.byId.has(id)) throw new HubvikError('UNKNOWN_DETECTOR', `unknown detector ${id}`);
    }
  }

  /** @returns {void} */
  _rebuildActive() {
    /** @type {any[]} */
    this.active = [];
    /** @type {Record<string, any[]>} */
    this.byType = Object.create(null);
    /** @type {Record<string, any[]>} */
    this.byTypePlain = Object.create(null);
    /** @type {Record<string, any[]>} */
    this.byTypePrep = Object.create(null);
    this.preparedType = Object.create(null);
    for (const type of EVENT_TYPES) {
      this.byType[type] = [];
      this.byTypePlain[type] = [];
      this.byTypePrep[type] = [];
    }
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
      const prepares = typeof det.prepare === 'function';
      for (const type of consumes) {
        this.byType[type].push(det);
        if (prepares) {
          this.byTypePrep[type].push(det);
          this.preparedType[type] = true;
        } else {
          this.byTypePlain[type].push(det);
        }
      }
    }
    this._horizonOn = horizonOn(this);
    this._graphOn = graphOn(this);
    this._peerOn = this.opts.peerSuggest === true;
    this._driftOn = this.opts.drift === true;
  }

  /**
   * Add a value to the frozen baseline.
   * @param {string} deviceId
   * @param {string} kind
   * @param {string} value
   * @returns {void}
   */
  allow(deviceId, kind, value) {
    if (this.opts.audit) /** @type {any} */ (this)._auditCall('allow', deviceId, { kind, value });
    if (!ALLOW_KINDS.includes(kind))
      throw new HubvikError('ALLOW_KIND_IS_INVALID', 'allow kind is invalid');
    if (typeof value !== 'string' || value.length === 0 || value.length > this.opts.maxString) {
      throw new HubvikError('ALLOW_VALUE_IS_INVALID', 'allow value is invalid');
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
    if (this.opts.audit)
      /** @type {any} */ (this)._auditCall('suppress', deviceId, { detectorId, opts });
    if (!this.byId.has(detectorId))
      throw new HubvikError('UNKNOWN_DETECTOR', `unknown detector ${detectorId}`);
    const device = /** @type {any} */ (this)._requireDevice(deviceId);
    /** @type {{ untilTs?: number, match?: string }} */
    const entry = {};
    if (opts.untilTs != null) {
      if (typeof opts.untilTs !== 'number' || !Number.isFinite(opts.untilTs)) {
        throw new HubvikError('UNTILTS_IS_INVALID', 'untilTs is invalid');
      }
      entry.untilTs = opts.untilTs;
    }
    if (opts.match != null) {
      if (typeof opts.match !== 'string')
        throw new HubvikError('MATCH_IS_INVALID', 'match is invalid');
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
    if (this.opts.audit) /** @type {any} */ (this)._auditCall('ack', anomalyId, {});
    if (typeof anomalyId !== 'string' || anomalyId.length === 0)
      throw new HubvikError('ANOMALY_ID_IS_INVALID', 'anomaly id is invalid');
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
      throw new HubvikError('DEVICE_ID_IS_INVALID', 'device id is invalid');
    }
    if (!CLASSES[classId]) throw new HubvikError('UNKNOWN_DEVICE_CLASS', 'unknown device class');
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
    if (this.opts.audit)
      /** @type {any} */ (this)._auditCall('setDeviceClass', deviceId, { classId });
  }

  /**
   * Drop every byte of state for a device.
   * @param {string} deviceId
   * @returns {void}
   */
  forget(deviceId) {
    if (this.opts.audit) /** @type {any} */ (this)._auditCall('forget', deviceId, {});
    this.devices.delete(deviceId);
    if (!this._removedSince) this._removedSince = [];
    this._removedSince.push(deviceId);
  }

  /**
   * @param {string} deviceId
   * @param {string | null} groupId
   * @returns {void}
   */
  setPeerGroup(deviceId, groupId) {
    if (typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)) {
      throw new HubvikError('DEVICE_ID_IS_INVALID', 'device id is invalid');
    }
    if (groupId != null && (typeof groupId !== 'string' || groupId.length > this.opts.maxString)) {
      throw new HubvikError('PEER_GROUP_IS_INVALID', 'peer group is invalid');
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
    if (this.opts.audit)
      /** @type {any} */ (this)._auditCall('setPeerGroup', deviceId, { groupId });
  }

  /**
   * Register a detector. Built-in ids cannot be replaced.
   * @param {any} detector
   * @returns {void}
   */
  use(detector) {
    this._assertDetector(detector);
    if (this.byId.has(detector.id))
      throw new HubvikError(
        'DETECTOR_IS_ALREADY_REGISTERED',
        `detector ${detector.id} is already registered`,
      );
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
    if (!Array.isArray(list))
      throw new HubvikError('INDICATORS_MUST_BE_AN_ARRAY', 'indicators must be an array');
    if (list.length > this.opts.maxIndicators)
      throw new HubvikError('ARRAY_INDICATORS_EXCEEDS_CAP', 'array indicators exceeds cap');
    const next = list.map((item) => validateIndicator(item));
    this.indicators = next;
    this.indicatorIndex = buildIndex(next);
    if (this.opts.audit)
      /** @type {any} */ (this)._auditCall('loadIndicators', '*', { count: next.length });
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
    if (this.opts.audit)
      /** @type {any} */ (this)._auditCall('loadRules', '*', { count: compiled.length });
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
    const snap = /** @type {any} */ (
      buildStats({
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
      })
    );
    if (this.opts.budget) snap.shed = /** @type {any} */ (this)._shedIds();
    if (this.opts.classSuggest) snap.classSuggestions = classSuggestions(this);
    if (this.opts.peerSuggest)
      snap.peerSuggestions = /** @type {any} */ (this)._peerSuggestions || [];
    return snap;
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
    if (this.opts.audit) /** @type {any} */ (this)._auditCall('feedback', key, { verdict });
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
    // Only the top of `_run` may reuse. Emit/windows/re-entrant feed get a fresh bag.
    if (engine._allowCtxReuse !== true) return engine._freshCtx(device, learning, ts);
    let bag = engine._feedCtx;
    if (!bag) {
      bag = engine._feedCtx = {
        learning: false,
        ts: 0,
        deviceId: '',
        /** @type {any} */
        _device: null,
        options: null,
        window: null,
        extra: null,
        learnMs: 0,
        engineStarted: null,
        indicatorIndex: null,
        policy: null,
        deviceClass: null,
        gatewayIp: null,
        dhcpServers: null,
        routers: null,
        ownBssids: null,
        zones: null,
        browserJa4: null,
        peerGroup: null,
        outlier: false,
        sequence: false,
        flowShape: false,
        abuseFacts: null,
        deviceCount: 0,
        scratch: null,
        lanEdges: null,
        bridges: null,
        /** @param {number} value */
        hour(value) {
          const current = bag._device;
          if (current && current.timeZone) return zonedClock(value, current.timeZone).hour;
          return engine.opts.hourOf(value);
        },
        /** @param {number} value */
        day(value) {
          const current = bag._device;
          if (current && current.timeZone) return zonedClock(value, current.timeZone).day;
          return engine.opts.dayOf(value);
        },
        peerSummaries() {
          return engine._peerSummaries || [];
        },
        mud() {
          return bag._device ? bag._device.mud || null : null;
        },
        summaryKey() {
          return engine._summaryKey || null;
        },
        peers() {
          const current = bag._device;
          const group = current && current.peerGroup;
          if (!group) return [];
          /** @type {any[]} */
          const list = [];
          for (const other of engine.devices.values()) {
            if (other !== current && other.peerGroup === group && other.seen) list.push(other);
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
        horizon() {
          return horizonView(bag._device);
        },
      };
    }
    bag._device = device;
    bag.learning = learning;
    bag.ts = ts;
    bag.deviceId = device.id;
    bag.options = null;
    bag.window = null;
    bag.extra = null;
    bag.learnMs = engine.opts.learnMs;
    bag.engineStarted = engine.startedAt;
    bag.indicatorIndex = engine.indicatorIndex;
    bag.policy = engine.opts.policy;
    bag.deviceClass = CLASSES[device.deviceClass] || null;
    bag.gatewayIp = engine.opts.gatewayIp;
    bag.dhcpServers = engine.opts.dhcpServers;
    bag.routers = engine.opts.routers;
    bag.ownBssids = engine.opts.ownBssids;
    bag.zones = engine.opts.zones;
    bag.browserJa4 = engine.opts.browserJa4;
    bag.peerGroup = device.peerGroup;
    bag.outlier = engine.opts.outlier === true;
    bag.sequence = engine.opts.sequence === true;
    bag.flowShape = engine.opts.flowShape === true;
    bag.abuseFacts = engine._abuse || [];
    bag.deviceCount = engine.devices.size;
    bag.scratch = engine.scratch;
    bag.lanEdges = device.lanEdges || null;
    bag.bridges = engine._bridges || (engine._bridges = new Set());
    return bag;
  }

  /**
   * One-shot context when feed re-enters during an anomaly listener.
   * @param {any} device
   * @param {boolean} learning
   * @param {number} ts
   * @returns {any}
   */
  _freshCtx(device, learning, ts) {
    const engine = /** @type {any} */ (this);
    return {
      learning,
      ts,
      deviceId: device.id,
      _device: device,
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
      outlier: engine.opts.outlier === true,
      sequence: engine.opts.sequence === true,
      flowShape: engine.opts.flowShape === true,
      abuseFacts: engine._abuse || [],
      deviceCount: engine.devices.size,
      scratch: engine.scratch,
      lanEdges: device.lanEdges || null,
      bridges: engine._bridges || (engine._bridges = new Set()),
      /** @param {number} value */
      hour(value) {
        if (device.timeZone) return zonedClock(value, device.timeZone).hour;
        return engine.opts.hourOf(value);
      },
      /** @param {number} value */
      day(value) {
        if (device.timeZone) return zonedClock(value, device.timeZone).day;
        return engine.opts.dayOf(value);
      },
      peerSummaries() {
        return engine._peerSummaries || [];
      },
      mud() {
        return device.mud || null;
      },
      summaryKey() {
        return engine._summaryKey || null;
      },
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
      horizon() {
        return horizonView(device);
      },
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
      throw new HubvikError('DETECTOR_MUST_BE_AN_OBJECT', 'detector must be an object');
    if (typeof detector.id !== 'string' || !/^(?:rule:)?[a-z0-9-]+$/.test(detector.id)) {
      throw new HubvikError('DETECTOR_ID_IS_INVALID', 'detector.id is invalid');
    }
    if (!Number.isInteger(detector.version) || detector.version < 1) {
      throw new HubvikError('DETECTOR_VERSION_IS_INVALID', 'detector.version is invalid');
    }
    if (!Array.isArray(detector.requires) || detector.requires.length === 0) {
      throw new HubvikError('DETECTOR_REQUIRES_IS_INVALID', 'detector.requires is invalid');
    }
    if (!detector.defaults || typeof detector.defaults !== 'object') {
      throw new HubvikError('DETECTOR_DEFAULTS_IS_INVALID', 'detector.defaults is invalid');
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
  if (!Array.isArray(raw))
    throw new HubvikError('CONSUMES_MUST_BE_AN_ARRAY', `${det.id} consumes must be an array`);
  /** @type {string[]} */
  const out = [];
  const seen = new Set();
  for (const type of raw) {
    if (typeof type !== 'string' || !EVENT_TYPE_SET.has(type)) {
      throw new HubvikError('CONSUMES_UNKNOWN_EVENT_TYPE', `${det.id} consumes unknown event type`);
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

/**
 * In-process shards. Worker threads wait for a Raspberry Pi 4 bench.
 * @param {object} [opts]
 */
function createShardedEngine(opts) {
  return sharded(createEngine, opts);
}

Object.assign(
  Engine.prototype,
  stateMethods,
  windowMethods,
  feedMethods,
  learningMethods,
  emitMethods,
  persistMethods,
  finishMethods,
  partgMethods,
  reportMethods,
);

/**
 * @param {any} engine
 */
function classSuggestions(engine) {
  /** @type {Record<string, { class: string, score: number, reasons: string[] }[]>} */
  const out = Object.create(null);
  for (const device of engine.devices.values()) {
    if (!device.classScores) continue;
    const rows = Object.keys(device.classScores)
      .map((classId) => ({
        class: classId,
        score: device.classScores[classId],
        reasons: (device.classReasons && device.classReasons[classId]) || [],
      }))
      .sort((a, b) => b.score - a.score || (a.class < b.class ? -1 : 1));
    if (rows.length > 0) out[device.id] = rows;
  }
  return out;
}

module.exports = { createEngine, createShardedEngine, Engine };
