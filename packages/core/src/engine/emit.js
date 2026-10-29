'use strict';

const { createHash } = require('node:crypto');
const { rememberAnomaly } = require('./feedback');
const { noteReport, noteShadow } = require('./report');
const { noteThreat } = require('./promote');
const { noteCampaign } = require('./campaigns');
const { spread } = require('./contagion');
const { noteIncident } = require('./incidents');
const ATTACK = require('../data/attack-map.json');

/**
 * Engine methods moved out of engine.js. Behavior is unchanged.
 * Each function is installed on Engine.prototype.
 */

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

module.exports = {
  /**
   * @this {any}
   * Why an anomaly fired. Older than `explainCap` returns null. Reading an id keeps it.
   * @param {string} anomalyId
   * @returns {any}
   */
  explain(anomalyId) {
    if (this.opts.scoring === 'lr' && typeof this._incidentContributions === 'function') {
      const contributions = this._incidentContributions(anomalyId);
      if (contributions) return contributions;
    }
    const id = String(anomalyId);
    const row = this._explain.get(id);
    if (!row) return null;
    this._explain.delete(id);
    this._explain.set(id, row);
    /** @type {any} */
    const copy = {
      ...row,
      suppressWith: row.suppressWith.map((/** @type {any} */ entry) => ({
        method: entry.method,
        args: entry.args.map((/** @type {any} */ arg) =>
          arg && typeof arg === 'object' && !Array.isArray(arg) ? { ...arg } : arg,
        ),
      })),
    };
    if (row.learned) copy.learned = { ...row.learned };
    return copy;
  },

  /**
   * @this {any}
   * @param {any} anomaly
   * @param {any} det
   * @param {any} item
   * @returns {void}
   */
  _rememberExplain(anomaly, det, item) {
    const supplied = item.explain && typeof item.explain === 'object' ? item.explain : null;
    const test = supplied && typeof supplied.test === 'string' ? supplied.test : 'match';
    const observed =
      supplied && supplied.observed != null ? supplied.observed : String(anomaly.actual);
    /** @type {any} */
    const row = {
      anomalyId: anomaly.id,
      detector: anomaly.detector,
      device: anomaly.device,
      ts: anomaly.ts,
      test,
      observed,
      evidence: anomaly.evidence == null ? [] : anomaly.evidence,
      suppressWith: this._suppressWith(det, anomaly, supplied),
    };
    if (supplied && supplied.threshold != null) row.threshold = supplied.threshold;
    if (supplied && supplied.formula != null) row.formula = supplied.formula;
    if (supplied && supplied.learned != null) row.learned = { ...supplied.learned };
    const numeric = test === 'gt' || test === 'gte' || test === 'lt';
    if (supplied && typeof supplied.margin === 'number') row.margin = supplied.margin;
    else if (numeric && typeof row.observed === 'number' && typeof row.threshold === 'number') {
      if (row.threshold !== 0) row.margin = row.observed / row.threshold;
    }
    if (this._explain.has(anomaly.id)) this._explain.delete(anomaly.id);
    this._explain.set(anomaly.id, row);
    while (this._explain.size > this.opts.explainCap) {
      const oldest = this._explain.keys().next().value;
      if (oldest == null) break;
      this._explain.delete(oldest);
    }
  },

  /**
   * @this {any}
   * @param {any} det
   * @param {any} anomaly
   * @param {any} supplied
   * @returns {{ method: string, args: any[] }[]}
   */
  _suppressWith(det, anomaly, supplied) {
    const day = 24 * 60 * 60 * 1000;
    const given = supplied && Array.isArray(supplied.suppressWith) ? supplied.suppressWith : null;
    /** @type {{ method: string, args: any[] }[]} */
    let list = given
      ? given.map((/** @type {any} */ entry) => ({
          method: entry.method,
          args: Array.isArray(entry.args) ? entry.args.slice() : [],
        }))
      : [
          {
            method: 'suppress',
            args: [
              anomaly.device,
              anomaly.detector,
              det.hardRule
                ? { match: String(anomaly.actual), untilTs: anomaly.ts + day }
                : { match: String(anomaly.actual) },
            ],
          },
        ];
    if (!det.hardRule) return list;
    list = list.filter((entry) => entry.method !== 'allow');
    return list.map((entry) => {
      if (entry.method !== 'suppress') return entry;
      const args = entry.args.slice();
      const opts = args[2] && typeof args[2] === 'object' ? { ...args[2] } : {};
      const cap = anomaly.ts + day;
      if (typeof opts.untilTs !== 'number' || opts.untilTs > cap) opts.untilTs = cap;
      args[2] = opts;
      return { method: 'suppress', args };
    });
  },

  /** @returns {object} */ /**
   * @this {any}
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
  },

  /**
   * @this {any}
   * @param {any} det
   * @returns {boolean}
   */
  _isShadow(det) {
    const over = this.opts.detectors[det.id];
    if (over && over.mode === 'live') return false;
    if (over && over.mode === 'shadow') return true;
    return Boolean(det.meta && det.meta.mode === 'shadow');
  },

  /**
   * @this {any}
   * A shadow detector stays off unless `shadow` selects it.
   * `detectors[id].enabled` wins, including an explicit false.
   * @param {any} det
   * @returns {boolean}
   */
  _shadowBlocked(det) {
    const over = this.opts.detectors[det.id];
    if (over && typeof over.enabled === 'boolean') return false;
    if (!this._isShadow(det)) return false;
    const shadow = this.opts.shadow;
    if (shadow === true) return false;
    if (Array.isArray(shadow)) return !shadow.includes(det.id);
    return true;
  },

  /**
   * @this {any}
   * Option overrides for the shadow copy of a live detector.
   * @param {any} det
   * @returns {Record<string, unknown> | null}
   */
  _canaryOverrides(det) {
    if (this._isShadow(det)) return null;
    const over = this.opts.detectors[det.id];
    if (!over || over.canary == null) return null;
    return over.canary;
  },

  /**
   * @this {any} @returns {void} */
  _notePromotions() {
    if (this._promotionsNoted) return;
    this._promotionsNoted = true;
    for (const det of this.registry) {
      const over = this.opts.detectors[det.id];
      if (det.meta && det.meta.mode === 'shadow' && over && over.mode === 'live') {
        this._warn('SHADOW_PROMOTED_BY_HOST', `${det.id} is live because the host set mode`);
      }
    }
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} det
   * @returns {any}
   */
  _canaryState(device, det) {
    if (!device.canary) device.canary = new Map();
    let state = device.canary.get(det.id);
    if (!state) {
      state = /** @type {any} */ (this)._freshState(det);
      device.canary.set(det.id, state);
    }
    return state;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} det
   * @param {any} anomaly
   */
  _noteShadow(device, det, anomaly) {
    let row = this._shadow[det.id];
    if (!row) {
      row = {
        fired: 0,
        devices: new Set(),
        bySeverity: Object.create(null),
        wouldJoinIncident: 0,
      };
      this._shadow[det.id] = row;
    }
    row.fired += 1;
    row.devices.add(device.id);
    const severity = String(anomaly.severity);
    row.bySeverity[severity] = (row.bySeverity[severity] || 0) + 1;
    const incident = device.incident;
    if (
      incident &&
      typeof anomaly.ts === 'number' &&
      anomaly.ts - incident.lastTs <= this.opts.incidentWindowMs
    ) {
      row.wouldJoinIncident += 1;
    }
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {string} id
   * @param {string} fp
   * @param {'live' | 'canary'} which
   */
  _rememberFp(device, id, fp, which) {
    if (!device.fp) device.fp = { live: new Map(), canary: new Map() };
    const bag = device.fp[which];
    let set = bag.get(id);
    if (!set) {
      set = new Set();
      bag.set(id, set);
    }
    set.add(String(fp));
  },

  /**
   * @this {any}
   * Count canary fingerprints once per closed window.
   * @param {any} device
   */
  _tallyCanaries(device) {
    const bag = device.fp;
    if (!bag) return;
    for (const id of Object.keys(this.opts.detectors)) {
      const over = this.opts.detectors[id];
      if (!over || over.canary == null) continue;
      const live = bag.live.get(id) || new Set();
      const canary = bag.canary.get(id) || new Set();
      if (!this._canary[id]) this._canary[id] = { liveOnly: 0, canaryOnly: 0, both: 0 };
      const row = this._canary[id];
      for (const fp of live) {
        if (canary.has(fp)) row.both += 1;
        else row.liveOnly += 1;
      }
      for (const fp of canary) {
        if (!live.has(fp)) row.canaryOnly += 1;
      }
    }
    bag.live.clear();
    bag.canary.clear();
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} det
   * @param {any} draft
   * @param {boolean} learning
   * @param {any} event
   * @param {'canary' | undefined} [route]
   */
  _take(device, det, draft, learning, event, route) {
    if (!draft) return;
    const shadow = route === 'canary' || this._isShadow(det);
    const list = Array.isArray(draft) ? draft : [draft];
    for (const item of list) {
      if (!item) continue;
      if (!shadow && det.id !== 'alert-storm' && this._overStorm(device, item.ts)) continue;
      if (this._muted(device, det.id, item)) {
        this.suppressCount += 1;
        continue;
      }
      const fingerprint = fingerprintOf(det.id, device.id, dedupKeyOf(item));
      /** @type {Record<string, unknown>} */
      const anomaly = {
        id: '',
        device: typeof item.device === 'string' ? item.device : device.id,
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
        fingerprint,
      };
      Object.defineProperty(anomaly, '_partgHard', {
        value: det.hardRule === true,
        enumerable: false,
        configurable: true,
      });
      if (event && event.observedAs) {
        /** @type {Record<string, unknown>} */ (anomaly.data).observedAs = event.observedAs;
      }
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
      this._decorateAnomaly(anomaly, det, item);
      if (this.opts.drift) {
        if (item.severity === 'high' || item.severity === 'critical')
          device._driftHighTs = anomaly.ts;
        if (!device._driftDets) device._driftDets = new Set();
        if (device._driftDets.size < 32) device._driftDets.add(det.id);
      }
      if (shadow) {
        this.shadowSeq += 1;
        anomaly.id = `s${this.shadowSeq}`;
        anomaly.shadow = true;
        if (route === 'canary') this._rememberFp(device, det.id, fingerprint, 'canary');
        else this._noteShadow(device, det, anomaly);
        this._rememberExplain(anomaly, det, item);
        if (typeof this._advanceTemplates === 'function') this._advanceTemplates(device, anomaly);
        delete anomaly._partgHard;
        noteShadow(this, anomaly);
        this.emit('shadow-anomaly', anomaly);
        continue;
      }
      this.seq += 1;
      this.anomalyCount += 1;
      anomaly.id = String(this.seq);
      if (this.opts.fdr) this._fdrPush(device, anomaly);
      if (this._canaryOverrides(det)) this._rememberFp(device, det.id, fingerprint, 'live');
      if (
        typeof this._tagAnnotation === 'function' &&
        this._tagAnnotation(device, det, anomaly, item)
      ) {
        anomaly._skipScore = true;
      }
      if (typeof this._finishFirmware === 'function') this._finishFirmware(item.ts);
      noteIncident(this, device, anomaly);
      if (typeof this._advanceTemplates === 'function') this._advanceTemplates(device, anomaly);
      noteCampaign(this, device, anomaly, event);
      this._rememberExplain(anomaly, det, item);
      delete anomaly._partgHard;
      delete anomaly._skipScore;
      rememberAnomaly(this, anomaly);
      noteReport(this, anomaly);
      noteThreat(this, device, det, anomaly);
      this.emit('anomaly', anomaly);
      spread(this, device, anomaly);
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
      /** @type {any} */ (this)._maybeDrift(device);
    }
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
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
    const limit = /** @type {any} */ (this)._optionsFor(det).maxPerMinute;
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
  },

  /**
   * @this {any}
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
    ctx.options = /** @type {any} */ (this)._optionsFor(det);
    const state = device.states ? /** @type {any} */ (this)._state(device, det) : {};
    this._take(device, det, det.check(state, event, ctx), learning, event);
  },

  /**
   * @this {any}
   * @param {string} code
   * @param {string} message
   * @param {string} [device]
   * @param {{ reason?: string, ts?: number, detector?: string, value?: string, shed?: string[], perEventUs?: number, series?: string, direction?: string, sinceTs?: number, detectors?: string[], groupId?: string, devices?: string[], brokenAt?: number }} [extra]
   */
  _warn(code, message, device, extra) {
    this.warningCount += 1;
    if (this._emittingWarning) return;
    this._emittingWarning = true;
    try {
      /** @type {{ code: string, message: string, device?: string, reason?: string, ts?: number, detector?: string, value?: string, shed?: string[], perEventUs?: number, series?: string, direction?: string, sinceTs?: number, detectors?: string[], groupId?: string, devices?: string[], brokenAt?: number }} */
      const warning = { code, message };
      if (device) warning.device = device;
      if (extra && extra.reason) warning.reason = extra.reason;
      if (extra && typeof extra.ts === 'number') warning.ts = extra.ts;
      if (extra && extra.detector) warning.detector = extra.detector;
      if (extra && extra.value != null) warning.value = extra.value;
      if (extra && extra.shed) warning.shed = extra.shed;
      if (extra && extra.perEventUs != null) warning.perEventUs = extra.perEventUs;
      if (extra && extra.series) warning.series = extra.series;
      if (extra && extra.direction) warning.direction = extra.direction;
      if (extra && typeof extra.sinceTs === 'number') warning.sinceTs = extra.sinceTs;
      if (extra && extra.detectors) warning.detectors = extra.detectors;
      if (extra && extra.groupId) warning.groupId = extra.groupId;
      if (extra && extra.devices) warning.devices = extra.devices;
      if (extra && typeof extra.brokenAt === 'number') warning.brokenAt = extra.brokenAt;
      this.emit('warning', warning);
    } finally {
      this._emittingWarning = false;
    }
  },
};
