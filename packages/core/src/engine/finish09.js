'use strict';

const { EventEmitter } = require('node:events');
const { createHmac, createHash } = require('node:crypto');
const { fnv1a32 } = require('./stats/hash');
const { canonical } = require('./baseline');
const { domainFamily } = require('./net');
const { applyProgress, thawStates, revive } = require('./checkpoint');
const { FORBIDDEN_KEYS } = require('./constants');
const { assertSafeKeys } = require('./validate/common');
const HINTS = require('../data/response-map.json');
const CONFIDENCE = require('../data/confidence.json');

const SHED_ORDER = ['T5', 'T3', 'T2', 'T1', 'T0'];
const WEEK = 7 * 24 * 3600 * 1000;
const SUMMARY_CAP = 1000;

/**
 * Release 0.9 behavior. Every option defaults off.
 * Installed on Engine.prototype.
 */
const methods = {
  /**
   * @this {any}
   * @param {string} deviceId
   * @param {string} zone
   * @returns {void}
   */
  setDeviceTimezone(deviceId, zone) {
    const device = blank(this, deviceId);
    if (!device) return;
    if (typeof zone !== 'string' || zone.length === 0 || zone.length > 64) {
      throw new TypeError('time zone is invalid');
    }
    try {
      Intl.DateTimeFormat('en-US', { timeZone: zone }).format(0);
    } catch {
      throw new TypeError('time zone is invalid');
    }
    device.timeZone = zone;
  },

  /**
   * @this {any}
   * @param {string} deviceId
   * @param {{ allows: object[] } | null} acl
   * @returns {void}
   */
  loadMud(deviceId, acl) {
    const device = blank(this, deviceId);
    if (!device) return;
    if (acl == null) {
      device.mud = null;
      return;
    }
    if (!acl || typeof acl !== 'object' || Array.isArray(acl)) {
      throw new TypeError('mud acl is invalid');
    }
    if (!Array.isArray(acl.allows) || acl.allows.length > 64) {
      throw new TypeError('mud allows is invalid');
    }
    /** @type {object[]} */
    const allows = [];
    for (const raw of acl.allows) {
      const row = /** @type {any} */ (raw);
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        throw new TypeError('mud allow is invalid');
      }
      for (const key of Object.keys(row)) {
        if (FORBIDDEN_KEYS.has(key)) throw new TypeError('mud allow is invalid');
      }
      /** @type {Record<string, unknown>} */
      const allow = {};
      if (row.dstPort != null) {
        if (!Number.isInteger(row.dstPort) || row.dstPort < 0 || row.dstPort > 65535) {
          throw new TypeError('mud dstPort is invalid');
        }
        allow.dstPort = row.dstPort;
      }
      if (row.proto != null) {
        if (typeof row.proto !== 'string' || row.proto.length > 16) {
          throw new TypeError('mud proto is invalid');
        }
        allow.proto = row.proto;
      }
      if (row.domain != null) {
        if (typeof row.domain !== 'string' || row.domain.length > 255) {
          throw new TypeError('mud domain is invalid');
        }
        allow.domain = row.domain.toLowerCase();
      }
      if (row.direction != null) {
        if (row.direction !== 'out' && row.direction !== 'in' && row.direction !== 'lan') {
          throw new TypeError('mud direction is invalid');
        }
        allow.direction = row.direction;
      }
      allows.push(allow);
    }
    device.mud = { allows };
  },

  /**
   * @this {any}
   * @param {number} sinceSeq
   * @param {{ sign?: string | Buffer }} [opts]
   */
  checkpointDelta(sinceSeq, opts = {}) {
    if (!Number.isInteger(sinceSeq) || sinceSeq < 0) throw new TypeError('sinceSeq is invalid');
    const from = this._deltaSeq || 0;
    if (sinceSeq !== from) throw new Error('checkpoint delta is out of order');
    const full = this.checkpoint({ createdAt: 0 });
    /** @type {Record<string, unknown>} */
    const devices = Object.create(null);
    for (const [id, row] of Object.entries(full.devices || {})) {
      const device = this.devices.get(id);
      if (device && (device.dirtySeq || 0) > sinceSeq) devices[id] = row;
    }
    const scratchJson = JSON.stringify(full.scratch || {});
    const scratch = scratchJson === this._scratchJson ? {} : full.scratch || {};
    /** @type {Record<string, unknown>} */
    const body = {
      fromSeq: sinceSeq,
      toSeq: this.stateSeq || 0,
      devices,
      scratch,
      removed: (this._removedSince || []).slice(),
      watermark: this.watermark,
      prevHash: this._deltaHash || '',
    };
    body.hash = deltaHash(body, opts.sign);
    this._deltaSeq = body.toSeq;
    this._deltaHash = body.hash;
    this._scratchJson = scratchJson;
    this._removedSince = [];
    return body;
  },

  /**
   * @this {any}
   * @param {any} delta
   * @param {{ sign?: string | Buffer }} [opts]
   * @returns {void}
   */
  applyDelta(delta, opts = {}) {
    if (!delta || typeof delta !== 'object' || Array.isArray(delta)) {
      throw new TypeError('checkpoint delta is invalid');
    }
    const from = this._deltaSeq || 0;
    if (delta.fromSeq !== from) throw new Error('checkpoint delta is out of order');
    if ((delta.prevHash || '') !== (this._deltaHash || '')) {
      throw new Error('checkpoint delta hash does not match');
    }
    const key = opts && opts.sign;
    const unsigned = { ...delta };
    delete unsigned.hash;
    if (deltaHash(unsigned, key) !== delta.hash) {
      throw new Error('checkpoint delta hash does not match');
    }
    const removed = Array.isArray(delta.removed) ? delta.removed : [];
    for (const id of removed) this.devices.delete(id);
    if (delta.devices && typeof delta.devices === 'object') {
      /** @type {Record<string, unknown>} */
      const devices = Object.create(null);
      for (const [id, row] of Object.entries(delta.devices)) {
        if (!row || typeof row !== 'object') continue;
        devices[id] = {
          peerGroup: /** @type {any} */ (row).peerGroup ?? null,
          deviceClass: /** @type {any} */ (row).deviceClass,
          detectors: /** @type {any} */ (row).detectors,
        };
      }
      this.importBaseline(
        {
          version: 3,
          createdAt: 0,
          engine: { windowMs: this.opts.windowMs, pkg: 'iotwarden' },
          devices,
        },
        { merge: true },
      );
      for (const [id, row] of Object.entries(delta.devices)) {
        const device = this.devices.get(id);
        if (!device || !row || typeof row !== 'object') continue;
        if (/** @type {any} */ (row).progress)
          applyProgress(device, /** @type {any} */ (row).progress);
        if (/** @type {any} */ (row).live)
          device.states = thawStates(/** @type {any} */ (row).live);
      }
    }
    if (delta.scratch && typeof delta.scratch === 'object' && !Array.isArray(delta.scratch)) {
      for (const key of Object.keys(delta.scratch)) {
        this.scratch.set(key, revive(delta.scratch[key]));
      }
    }
    if (typeof delta.watermark === 'number') {
      this.watermark = delta.watermark;
      this.lastEventTs = delta.watermark;
    }
    this._deltaSeq = delta.toSeq;
    this.stateSeq = delta.toSeq;
    this._deltaHash = delta.hash;
  },

  /**
   * @this {any}
   * @param {{ key: string | Buffer, gatewayId: string }} opts
   */
  exportSummary(opts) {
    if (!opts || typeof opts.gatewayId !== 'string' || opts.gatewayId.length === 0) {
      throw new TypeError('gatewayId is invalid');
    }
    if (typeof opts.key !== 'string' && !Buffer.isBuffer(opts.key)) {
      throw new TypeError('summary key is invalid');
    }
    /** @type {Map<string, { families: Set<string>, ports: Set<number> }>} */
    const groups = new Map();
    for (const device of this.devices.values()) {
      if (!device.peerGroup || !device.seen) continue;
      let group = groups.get(device.peerGroup);
      if (!group) {
        group = { families: new Set(), ports: new Set() };
        groups.set(device.peerGroup, group);
      }
      const state = device.states.get('peer-divergence');
      if (state && state.families) {
        for (const family of state.families) {
          if (group.families.size < 64) group.families.add(family);
        }
      }
    }
    const body = {
      gatewayId: opts.gatewayId,
      ts: this.watermark || 0,
      groups: [...groups.entries()].map(([id, group]) => ({
        id: token(opts.key, id),
        families: [...group.families].map((family) => token(opts.key, family)),
        ports: [...group.ports],
        hll: { p: 10, count: group.families.size },
      })),
    };
    return { ...body, sig: { alg: 'HMAC-SHA256', mac: macOf(opts.key, body) } };
  },

  /**
   * @this {any}
   * @param {any[]} list
   * @param {{ verify?: string | Buffer }} [opts]
   * @returns {void}
   */
  importPeerSummaries(list, opts = {}) {
    if (!Array.isArray(list)) throw new TypeError('summaries must be an array');
    if (list.length > SUMMARY_CAP) throw new Error('array summaries exceeds cap');
    /** @type {any[]} */
    const next = [];
    for (const row of list) {
      if (!row || typeof row !== 'object' || Array.isArray(row)) {
        throw new TypeError('summary is invalid');
      }
      assertSafeKeys(row, 'summary');
      if (row.groups != null && !Array.isArray(row.groups)) {
        throw new TypeError('summary groups are invalid');
      }
      for (const group of row.groups || []) {
        if (!group || typeof group !== 'object' || Array.isArray(group)) {
          throw new TypeError('summary group is invalid');
        }
        assertSafeKeys(group, 'summary.group');
      }
      if (opts.verify != null) {
        const unsigned = { ...row };
        delete unsigned.sig;
        const mac = row.sig && row.sig.mac;
        if (mac !== macOf(opts.verify, unsigned)) throw new Error('summary signature is invalid');
      }
      const age = (this.watermark || 0) - (row.ts || 0);
      if (this.watermark != null && age > WEEK) continue;
      next.push(row);
    }
    const previous = this._peerSummaries || [];
    const previousKey = this._summaryKey;
    this._peerSummaries = next;
    if (opts.verify != null) this._summaryKey = opts.verify;
    try {
      notePoison(this);
    } catch (err) {
      this._peerSummaries = previous;
      this._summaryKey = previousKey;
      throw err;
    }
  },

  /**
   * @this {any}
   * @param {bigint | number} delta
   * @returns {void}
   */
  _budgetAccount(delta) {
    const budget = this.opts.budget;
    if (!budget) return;
    const us = typeof delta === 'bigint' ? Number(delta / 1000n) : delta / 1000;
    this._budgetUs = (this._budgetUs || 0) + us;
    this._budgetN = (this._budgetN || 0) + 1;
    if (this._budgetN < budget.sampleEvery) return;
    const mean = this._budgetUs / this._budgetN;
    this._budgetUs = 0;
    this._budgetN = 0;
    if (mean > budget.perEventUs) {
      this._underWindows = 0;
      if ((this._shedSteps || 0) < SHED_ORDER.length) {
        this._shedSteps = (this._shedSteps || 0) + 1;
        this._warn('DEGRADED', 'shed a tier to stay inside the event budget', undefined, {
          shed: this._shedIds(),
          perEventUs: mean,
        });
      } else this._shedLearn = true;
      return;
    }
    const window = Math.floor((this.watermark || 0) / this.opts.windowMs);
    if (window === this._budgetWindow) return;
    this._budgetWindow = window;
    this._underWindows = (this._underWindows || 0) + 1;
    if (this._underWindows >= budget.recoverWindows && (this._shedSteps || 0) > 0) {
      this._shedSteps -= 1;
      this._underWindows = 0;
      if (this._shedSteps < SHED_ORDER.length) this._shedLearn = false;
      this._warn('RECOVERED', 'restored a shed tier', undefined, { shed: this._shedIds() });
    }
  },

  /**
   * @this {any}
   * @param {any} det
   * @returns {boolean}
   */
  _sheds(det) {
    if (!this.opts.budget || !this._shedSteps || det.hardRule) return false;
    const shed = new Set(SHED_ORDER.slice(0, this._shedSteps));
    return (det.requires || []).some((/** @type {string} */ tier) => shed.has(tier));
  },

  /**
   * @this {any}
   * @returns {string[]}
   */
  _shedIds() {
    /** @type {string[]} */
    const ids = [];
    for (const det of this.registry) {
      if (this._sheds(det)) ids.push(det.id);
    }
    return ids;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} event
   * @returns {void}
   */
  _noteClass(device, event) {
    if (!this.opts.classSuggest || device.mode !== 'learning') return;
    const scores = device.classScores || (device.classScores = Object.create(null));
    const reasons = device.classReasons || (device.classReasons = Object.create(null));
    /**
     * @param {string} classId
     * @param {number} weight
     * @param {string} reason
     */
    const add = (classId, weight, reason) => {
      scores[classId] = Math.min(1, (scores[classId] || 0) + weight);
      const list = reasons[classId] || (reasons[classId] = []);
      if (!list.includes(reason) && list.length < 8) list.push(reason);
    };
    if (event.type === 'flow' && event.dstPort === 554) add('camera', 0.5, 'rtsp');
    if (event.type === 'flow' && event.direction === 'out' && (event.bytesOut || 0) > 125000) {
      add('camera', 0.5, 'upload');
    }
    noteFamilies(device, event);
    if (device.classBrowser && device.classFam && device.classFam.names.size > 30) {
      add('smart-tv', 0.5, 'browser-ja4-and-families');
    }
    if (
      event.type === 'tls' &&
      Array.isArray(this.opts.browserJa4) &&
      this.opts.browserJa4.includes(event.ja4)
    ) {
      device.classBrowser = true;
      if (device.classFam && device.classFam.names.size > 30) {
        add('smart-tv', 0.5, 'browser-ja4-and-families');
      }
    }
    if (
      event.type === 'app' &&
      event.role === 'server' &&
      (event.proto === 'bacnet' || event.proto === 'modbus')
    ) {
      add('hvac-controller', 0.7, event.proto);
    }
    if (
      event.type === 'flow' &&
      event.direction === 'in' &&
      [631, 9100, 515].includes(event.dstPort)
    ) {
      add('printer', 0.6, 'listen');
    }
    if (
      event.type === 'flow' &&
      event.direction === 'in' &&
      [445, 2049, 548].includes(event.dstPort)
    ) {
      add('nas', 0.6, 'listen');
    }
    if (event.type === 'app' && event.proto === 'mqtt') {
      const op = String(event.op).toLowerCase();
      if (op !== 'publish') {
        device.classMqttOther = true;
        delete scores.thermostat;
        delete reasons.thermostat;
      }
      const hour = Math.floor((event.ts || 0) / 3_600_000);
      const bucket = device.classHour || (device.classHour = { hour, bytes: 0 });
      if (bucket.hour !== hour) {
        bucket.hour = hour;
        bucket.bytes = 0;
      }
      if (op === 'publish' && !device.classMqttOther && bucket.bytes < 50 * 1024) {
        add('thermostat', 0.4, 'mqtt');
      }
    }
    if (event.type === 'flow') {
      const hour = Math.floor((event.ts || 0) / 3_600_000);
      const bucket = device.classHour || (device.classHour = { hour, bytes: 0 });
      if (bucket.hour !== hour) {
        bucket.hour = hour;
        bucket.bytes = 0;
      }
      bucket.bytes += (event.bytesOut || 0) + (event.bytesIn || 0);
    }
    const ranked = Object.keys(scores)
      .map((classId) => ({
        class: classId,
        score: scores[classId],
        reasons: reasons[classId] || [],
      }))
      .sort((a, b) => b.score - a.score || (a.class < b.class ? -1 : 1));
    const top = ranked[0];
    const second = ranked[1] ? ranked[1].score : 0;
    if (top && top.score >= 0.7 && top.score - second >= 0.2 && !device.classSuggested) {
      device.classSuggested = true;
      this._warn('CLASS_SUGGESTED', `suggested class ${top.class}`, device.id, { ts: event.ts });
    }
  },

  /**
   * @this {any}
   * @param {any} anomaly
   * @param {any} det
   * @param {any} item
   * @returns {void}
   */
  _decorateAnomaly(anomaly, det, item) {
    if (this.opts.calibratedConfidence && !det.hardRule) {
      if (typeof item.margin === 'number' && item.margin > 0) {
        const raw = 0.5 + 0.5 * Math.tanh(1.5 * Math.log(item.margin));
        anomaly.confidence = Math.min(0.99, Math.max(0.05, raw));
      } else if (typeof (/** @type {Record<string, number>} */ (CONFIDENCE)[det.id]) === 'number') {
        anomaly.confidence = /** @type {Record<string, number>} */ (CONFIDENCE)[det.id];
      }
    }
    if (this.opts.responseHints) {
      const rows = /** @type {Record<string, { action: string, minConfidence: number }[]>} */ (
        HINTS
      )[det.id];
      if (Array.isArray(rows)) {
        const hints = rows
          .filter((row) => !String(det.id).startsWith('ot-') || row.action === 'review')
          .map((row) => ({
            action: row.action,
            target: String(anomaly.device),
            reversible: true,
            minConfidence: row.minConfidence,
          }));
        if (hints.length > 0) anomaly.response = hints;
      }
    }
    const redact = this.opts.redact;
    if (!redact) return;
    walkRedact(anomaly, redact.fields, redact.key, redact.map || null);
  },
};

/**
 * @param {any} device
 * @param {any} event
 */
function noteFamilies(device, event) {
  const family = domainFamily(event.dstName || event.qname || event.sni || event.dst);
  if (!family) return;
  const day = Math.floor((event.ts || 0) / 86_400_000);
  if (!device.classFam || device.classFam.day !== day) device.classFam = { day, names: new Set() };
  if (device.classFam.names.size < 64) device.classFam.names.add(family);
}

/**
 * @param {any} engine
 * @param {string} deviceId
 */
function blank(engine, deviceId) {
  if (typeof deviceId !== 'string' || deviceId.length === 0 || FORBIDDEN_KEYS.has(deviceId)) {
    throw new TypeError('device id is invalid');
  }
  let device = engine.devices.get(deviceId);
  if (!device) {
    if (engine.devices.size >= engine.opts.maxDevices) {
      engine._warn('STATE_CAP', 'device cap reached', deviceId);
      return null;
    }
    device = engine._blank(deviceId);
    engine.devices.set(deviceId, device);
  }
  return device;
}

/**
 * @param {Record<string, unknown>} body
 * @param {string | Buffer} [key]
 */
function deltaHash(body, key) {
  const payload = `${body.prevHash || ''}${canonical(body)}`;
  if (key == null) return createHash('sha256').update(payload).digest('hex');
  return createHmac('sha256', key).update(payload).digest('hex');
}

/**
 * @param {string | Buffer} key
 * @param {string} value
 */
function token(key, value) {
  return createHmac('sha256', key).update(value).digest('hex').slice(0, 16);
}

/**
 * @param {string | Buffer} key
 * @param {object} body
 */
function macOf(key, body) {
  return createHmac('sha256', key).update(canonical(body)).digest('hex');
}

/**
 * @param {any} engine
 */
function notePoison(engine) {
  const det = engine.byId.get('fleet-baseline-poisoning');
  if (!det || engine._shadowBlocked(det)) return;
  const summaries = engine._peerSummaries || [];
  /** @type {Set<string>} */
  const local = new Set();
  let peers = 0;
  for (const device of engine.devices.values()) {
    const state = device.states && device.states.get('peer-divergence');
    if (!state || !state.families || state.families.size === 0) continue;
    peers += 1;
    for (const family of state.families) {
      local.add(engine._summaryKey ? token(engine._summaryKey, family) : family);
    }
  }
  if (peers === 0) return;
  for (const device of engine.devices.values()) {
    if (!device.seen) continue;
    for (const summary of summaries) {
      for (const group of summary.groups || []) {
        for (const family of (group.families || []).slice(0, 1000)) {
          if (local.has(family)) continue;
          const ctx = engine._ctx(device, false, summary.ts || 0);
          ctx.options = engine._optionsFor(det);
          const draft = det.check(engine._state(device, det), { ts: summary.ts || 0, family }, ctx);
          engine._take(device, det, draft, false, null);
        }
      }
    }
  }
}

/**
 * @param {any} node
 * @param {string[]} fields
 * @param {string | Buffer} key
 * @param {((token: string, value: string) => void) | null} map
 * @param {Set<object>} [seen]
 */
function walkRedact(node, fields, key, map, seen = new Set()) {
  if (!node || typeof node !== 'object' || seen.has(node)) return;
  seen.add(node);
  if (Array.isArray(node)) {
    for (const item of node) walkRedact(item, fields, key, map, seen);
    return;
  }
  for (const field of fields) {
    if (typeof node[field] !== 'string') continue;
    const value = node[field];
    const next = `r_${token(key, value)}`;
    if (map) map(next, value);
    node[field] = next;
  }
  for (const value of Object.values(node)) walkRedact(value, fields, key, map, seen);
}

/**
 * Local hour and day in an IANA zone.
 * @param {number} ts
 * @param {string} zone
 */
function zonedClock(ts, zone) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: zone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
  }).formatToParts(new Date(ts));
  /** @type {Record<string, string>} */
  const bag = {};
  for (const part of parts) bag[part.type] = part.value;
  return {
    hour: Number(bag.hour) % 24,
    day: Number(bag.year) * 10000 + Number(bag.month) * 100 + Number(bag.day),
  };
}

/**
 * @param {(opts?: object) => any} createEngine
 * @param {any} raw
 */
function createShardedEngine(createEngine, raw) {
  const opts = raw || {};
  if (opts.inline !== true) {
    throw new Error('worker shards wait for a Raspberry Pi 4 bench');
  }
  const shards = opts.shards;
  if (!Number.isInteger(shards) || shards < 1 || shards > 64) {
    throw new TypeError('shards must be an integer from 1 to 64');
  }
  const rest = { ...opts };
  delete rest.shards;
  delete rest.inline;
  /** @type {any[]} */
  const engines = [];
  for (let i = 0; i < shards; i += 1) engines.push(createEngine(rest));
  return new Sharded(engines);
}

const T4 = new Set(['arp', 'dhcp', 'ra', 'discovery', 'nd', 'wifi']);

/**
 * A device can learn flows on one shard and link-layer state on shard 0.
 * Keep the detector state that actually learned something.
 * @param {any} left
 * @param {any} right
 */
function mergeShardDevice(left, right) {
  /** @type {Record<string, any>} */
  const detectors = Object.create(null);
  for (const [id, row] of Object.entries(left.detectors || {})) detectors[id] = row;
  for (const [id, row] of Object.entries(right.detectors || {})) {
    const prev = detectors[id];
    const next = /** @type {any} */ (row);
    if (!prev) detectors[id] = next;
    else detectors[id] = { v: prev.v || next.v, state: mergeState(prev.state, next.state) };
  }
  /** @type {Record<string, any>} */
  const merged = { peerGroup: left.peerGroup ?? right.peerGroup ?? null, detectors };
  const deviceClass = left.deviceClass || right.deviceClass;
  if (deviceClass) merged.deviceClass = deviceClass;
  return merged;
}

/**
 * @param {any} left
 * @param {any} right
 */
function mergeState(left, right) {
  if (left == null) return right;
  if (right == null) return left;
  if (
    typeof left !== 'object' ||
    typeof right !== 'object' ||
    Array.isArray(left) ||
    Array.isArray(right)
  ) {
    return stateWeight(left) >= stateWeight(right) ? left : right;
  }
  const out = { ...left };
  for (const [key, value] of Object.entries(right)) {
    if (key === 'lastTs' && typeof out.lastTs === 'number' && typeof value === 'number') {
      out.lastTs = Math.max(out.lastTs, value);
    } else if (out[key] == null || out[key] === false) out[key] = value;
    else if (
      typeof out[key] === 'number' &&
      typeof value === 'number' &&
      stateWeight(value) > stateWeight(out[key])
    ) {
      out[key] = value;
    } else if (value != null && value !== false && stateWeight(value) > stateWeight(out[key])) {
      out[key] = value;
    }
  }
  return out;
}

/**
 * @param {any} state
 * @returns {number}
 */
function stateWeight(state) {
  if (typeof state === 'number') return state === 0 ? 0 : Math.abs(state) + 1;
  if (state == null || state === false) return 0;
  const text = JSON.stringify(state);
  if (text == null) return 0;
  return text.replace(/null|false|\[\]|\{\}|:0(?=[,}\]])/g, '').length;
}

class Sharded extends EventEmitter {
  /**
   * @param {any[]} engines
   */
  constructor(engines) {
    super();
    this.engines = engines;
    /** @type {Map<string, number>} */
    this.deviceShard = new Map();
    /** @type {Map<string, number>} */
    this.groupShard = new Map();
    for (const engine of engines) {
      for (const name of [
        'anomaly',
        'shadow-anomaly',
        'warning',
        'incident',
        'learned',
        'device-new',
      ]) {
        engine.on(name, (/** @type {any} */ payload) => this.emit(name, payload));
      }
    }
  }

  /**
   * @param {any} event
   * @returns {void}
   */
  feed(event) {
    const type = event && event.type ? event.type : 'summary';
    const index = T4.has(type) ? 0 : this._shard(event && event.device);
    this.engines[index].feed(event);
  }

  /**
   * @param {any[]} events
   * @returns {void}
   */
  feedBatch(events) {
    if (!Array.isArray(events)) throw new TypeError('events must be an array');
    for (const event of events) this.feed(event);
  }

  /**
   * @param {number} [now]
   * @returns {void}
   */
  flush(now) {
    for (const engine of this.engines) engine.flush(now);
  }

  /**
   * @param {string} [deviceId]
   * @returns {void}
   */
  lock(deviceId) {
    if (deviceId == null) {
      for (const engine of this.engines) engine.lock();
      return;
    }
    this._shardEngine(deviceId).lock(deviceId);
  }

  /**
   * @param {number} [now]
   * @returns {void}
   */
  tick(now) {
    for (const engine of this.engines) engine.tick(now);
  }

  /**
   * @param {string} deviceId
   * @param {string | null} groupId
   * @returns {void}
   */
  setPeerGroup(deviceId, groupId) {
    if (groupId) {
      const shard = fnv1a32(groupId) % this.engines.length;
      if (!this.groupShard.has(groupId)) this.groupShard.set(groupId, shard);
      this.deviceShard.set(deviceId, this.groupShard.get(groupId) ?? shard);
    }
    this._shardEngine(deviceId).setPeerGroup(deviceId, groupId);
  }

  /**
   * @param {{ createdAt?: number }} [opts]
   */
  exportBaseline(opts) {
    const parts = this.engines.map((engine) => engine.exportBaseline(opts));
    /** @type {Record<string, any>} */
    const devices = Object.create(null);
    for (const part of parts) {
      for (const [id, row] of Object.entries(part.devices || {})) {
        devices[id] = devices[id] ? mergeShardDevice(devices[id], row) : row;
      }
    }
    return { ...parts[0], devices };
  }

  /** @returns {Promise<void>} */
  drain() {
    return Promise.resolve();
  }

  /**
   * @param {string} deviceId
   */
  _shard(deviceId) {
    const known = this.deviceShard.get(deviceId);
    if (known != null) return known;
    const index = fnv1a32(String(deviceId || '')) % this.engines.length;
    this.deviceShard.set(deviceId, index);
    return index;
  }

  /**
   * @param {string} deviceId
   */
  _shardEngine(deviceId) {
    return this.engines[this._shard(deviceId)];
  }
}

module.exports = { methods, createShardedEngine, zonedClock };
