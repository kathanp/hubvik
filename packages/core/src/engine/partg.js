'use strict';

const { HubvikError } = require('../errors');

const annotations = require('./annotations');
const audit = require('./audit');
const drift = require('./drift');
const { domainFamily } = require('./net');
const { add, bands, createMinHash, jaccard } = require('./stats/minhash');
const { createWelford, push: pushWelford } = require('./stats/welford');
const { payload: incidentPayload } = require('./incidents');
const { advance, compile, createBook } = require('./templates');
const LR = require('../data/lr.json');

const DAY = 86400000;
const HALF = 6 * 3600000;
const PRIOR = Math.log(0.001 / 0.999);
const LEVELS = new Set(['low', 'normal', 'high', 'safety']);
const POST = { low: 0.9, normal: 0.8, high: 0.6, safety: 0.5 };
const ADD = { low: 80, normal: 70, high: 55, safety: 45 };
const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Group A and B behavior. Every option defaults off, and these methods no-op then.
 */
const partgMethods = {
  /**
   * @this {any}
   * @param {string} target
   * @param {any} spec
   * @returns {string}
   */
  annotate(target, spec) {
    const book = this._annBook || (this._annBook = annotations.createAnnotationBook());
    const id = annotations.add(book, target, spec, this.watermark || 0);
    const abuse = annotations.abuse(book, target, spec.fromTs);
    if (abuse.deviceSpam || abuse.starSpam) {
      this._warn(
        'ANNOTATION_ABUSE',
        'annotation rate is above the cap',
        target === '*' ? null : target,
      );
    }
    this._auditCall('annotate', target, spec, spec && spec.operator);
    return id;
  },

  /**
   * @this {any}
   * @param {string} id
   * @returns {boolean}
   */
  removeAnnotation(id) {
    if (!this._annBook) return false;
    const ok = annotations.remove(this._annBook, id);
    if (ok) this._auditCall('removeAnnotation', id, {});
    return ok;
  },

  /**
   * @this {any}
   * @param {{ device?: string, activeAt?: number }} [query]
   * @returns {any[]}
   */
  annotations(query) {
    if (!this._annBook) return [];
    return annotations.list(this._annBook, query || {});
  },

  /**
   * @this {any}
   * @param {string} deviceId
   * @param {string} level
   * @returns {void}
   */
  setDeviceCriticality(deviceId, level) {
    if (!LEVELS.has(level)) {
      throw new HubvikError('CRITICALITY_IS_INVALID', 'criticality is invalid');
    }
    this._requireDevice(deviceId);
    if (!this._criticality) this._criticality = new Map();
    this._criticality.set(deviceId, level);
    this._auditCall('setDeviceCriticality', deviceId, { level });
  },

  /**
   * @this {any}
   * @param {unknown} list
   * @returns {void}
   */
  loadTemplates(list) {
    const known = new Set(this.byId.keys());
    const compiled = compile(list, known);
    this._templates = createBook();
    this._templates.templates = compiled;
    this._auditCall('loadTemplates', '*', { count: compiled.length });
  },

  /**
   * @this {any}
   * @param {{ sinceSeq?: number }} [opts]
   * @returns {any[]}
   */
  auditLog(opts) {
    if (!this._audit) return [];
    return audit.auditLog(this._audit, opts || {});
  },

  /**
   * @this {any}
   * @returns {{ ok: boolean, brokenAt?: number }}
   */
  verifyAudit() {
    if (!this._audit) return { ok: true };
    return audit.verifyAudit(this._audit);
  },

  /**
   * @this {any}
   * @param {string} kind
   * @param {string} target
   * @param {any} args
   * @param {string} [operator]
   * @returns {void}
   */
  _auditCall(kind, target, args, operator) {
    if (!this.opts.audit) return;
    if (!this._audit) this._audit = audit.createAuditLog();
    /** @type {{ key?: string }} */
    const opts = {};
    if (typeof this._auditKey === 'string') {
      if (this._audit.records.length === 0 || this._audit.key === this._auditKey) {
        opts.key = this._auditKey;
      }
    }
    audit.append(
      this._audit,
      {
        ts: this.watermark || 0,
        kind,
        operator: typeof operator === 'string' ? operator : null,
        target: String(target),
        args,
      },
      opts,
    );
    if (!this._abuse) this._abuse = [];
    const row = args && typeof args === 'object' ? /** @type {any} */ (args) : {};
    this._abuse.push({
      ts: this.watermark || 0,
      kind,
      operator: typeof operator === 'string' ? operator : null,
      target: String(target),
      detectorId: typeof row.detectorId === 'string' ? row.detectorId : null,
      fromTs: typeof row.fromTs === 'number' ? row.fromTs : null,
      untilTs: typeof row.untilTs === 'number' ? row.untilTs : null,
    });
    if (this._abuse.length > 256) this._abuse.shift();
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} det
   * @param {any} anomaly
   * @param {any} item
   * @returns {boolean}
   */
  _tagAnnotation(device, det, anomaly, item) {
    if (!this._annBook) return false;
    const hard = det.hardRule === true;
    if (!annotations.covers(this._annBook, device.id, det.id, anomaly.ts, hard)) return false;
    const rows = annotations.list(this._annBook, { device: device.id, activeAt: anomaly.ts });
    anomaly.context = rows
      .filter((row) => !row.detectors || row.detectors.includes(det.id))
      .map((row) => ({ annotationId: row.id, kind: row.kind }));
    if (item && item.explain && item.explain.test === 'new-member') {
      if (!this._firmwareHits) this._firmwareHits = new Map();
      for (const row of rows) {
        if (row.kind !== 'firmware-update') continue;
        const set = this._firmwareHits.get(row.id) || new Set();
        set.add(det.id);
        this._firmwareHits.set(row.id, set);
      }
    }
    return !hard;
  },

  /**
   * @this {any}
   * @param {number} ts
   * @returns {void}
   */
  _finishFirmware(ts) {
    if (!this._annBook) return;
    for (const row of annotations.endedFirmware(this._annBook, ts)) {
      const fired = this._firmwareHits ? this._firmwareHits.get(row.id) : null;
      this._warn(
        'RELEARN_SUGGESTED',
        'firmware-update annotation ended',
        row.target === '*' ? null : row.target,
        { detectors: fired ? [...fired] : [] },
      );
      annotations.markSuggested(this._annBook, row.id);
    }
  },

  /**
   * @this {any}
   * @param {any} anomaly
   * @returns {number}
   */
  _llrOf(anomaly) {
    const table = /** @type {Record<string, { llr?: number, hardRule?: boolean }>} */ (
      LR.detectors
    );
    const row = table && table[anomaly.detector];
    let llr = row && typeof row.llr === 'number' ? row.llr : 1;
    if (llr < -3) llr = -3;
    if (llr > 6) llr = 6;
    anomaly.llr = llr;
    return llr;
  },

  /**
   * @this {any}
   * @param {any} incident
   * @param {any} anomaly
   * @param {number} llr
   * @returns {void}
   */
  _addLlr(incident, anomaly, llr) {
    if (!incident.contrib) incident.contrib = [];
    const group = anomaly.dedupGroup || anomaly.category || anomaly.id;
    const prev = incident.contrib.find((/** @type {any} */ row) => row.group === group);
    if (prev && prev.llr >= llr) return;
    if (prev) {
      prev.llr = llr;
      prev.ts = anomaly.ts;
      prev.anomalyId = anomaly.id;
    } else
      incident.contrib.push({
        group,
        detector: anomaly.detector,
        llr,
        anomalyId: anomaly.id,
        stage: stageOf(anomaly),
        ts: anomaly.ts,
      });
  },

  /**
   * @this {any}
   * @param {any} incident
   * @param {number} ts
   * @returns {void}
   */
  _posterior(incident, ts) {
    const stages = new Set();
    /** @type {Record<string, number>} */
    const stageSum = Object.create(null);
    let sum = PRIOR;
    for (const row of incident.contrib || []) {
      const age = Math.max(0, ts - (typeof row.ts === 'number' ? row.ts : incident.lastTs));
      const decay = 0.5 ** (age / HALF);
      let part = row.llr * (row.decay == null ? decay : row.decay);
      const stage = row.stage || 'none';
      const used = stageSum[stage] || 0;
      if (used >= 4 && part > 0) part = 0;
      stageSum[stage] = used + Math.max(0, part);
      stages.add(stage);
      sum += part;
    }
    if (stages.size > 1) sum += stages.size - 1;
    if (incident.llrBonus) sum += Math.min(3, incident.llrBonus);
    const posterior = 1 / (1 + Math.exp(-sum));
    incident.posterior = posterior;
    incident.score = Math.round(Math.min(100, posterior * 100));
    incident.severity =
      posterior >= 0.8
        ? 'critical'
        : posterior >= 0.5
          ? 'high'
          : posterior >= 0.2
            ? 'medium'
            : 'low';
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} incident
   * @param {any} anomaly
   * @param {string} kind
   * @returns {void}
   */
  _considerAlert(device, incident, anomaly, kind) {
    if (!this.opts.alerts) return;
    const level = (this._criticality && this._criticality.get(device.id)) || 'normal';
    const hard = anomaly && anomaly._partgHard === true;
    let fire = hard || kind === 'campaign' || kind === 'template';
    let severity = anomaly ? anomaly.severity : incident.severity;
    if (incident) {
      const bar =
        this.opts.scoring === 'lr'
          ? POST[/** @type {keyof typeof POST} */ (level)]
          : ADD[/** @type {keyof typeof ADD} */ (level)];
      const value = this.opts.scoring === 'lr' ? incident.posterior || 0 : incident.score;
      if (value >= bar) fire = true;
      severity = incident.severity;
    }
    if (anomaly && anomaly.detector === 'went-silent' && level === 'safety') {
      fire = true;
      severity = 'high';
    }
    if (!fire) return;
    this._emitAlert(
      device.id,
      kind,
      incident ? incident.id : anomaly.id,
      severity,
      anomaly ? anomaly.ts : incident.lastTs,
      anomaly,
      incident,
    );
  },

  /**
   * @this {any}
   * @param {string} deviceId
   * @param {string} kind
   * @param {string} refId
   * @param {string} severity
   * @param {number} ts
   * @param {any} anomaly
   * @param {any} incident
   * @returns {void}
   */
  _emitAlert(deviceId, kind, refId, severity, ts, anomaly, incident) {
    if (!this._alertState) this._alertState = new Map();
    const state = this._alertState.get(deviceId) || {
      day: null,
      count: 0,
      last: new Map(),
      digest: [],
    };
    const day = Math.floor(ts / DAY);
    if (state.day !== day) {
      if (state.digest.length > 0) {
        this.emit('alert', digestOf(deviceId, state));
      }
      state.day = day;
      state.count = 0;
      state.digest = [];
    }
    const hard = anomaly && anomaly._partgHard === true;
    const critical = severity === 'critical';
    const templateAlert = kind === 'template';
    const prev = state.last.get(refId);
    if (
      !templateAlert &&
      prev &&
      ts - prev.ts < 6 * 3600000 &&
      rankOf(severity) <= rankOf(prev.severity)
    ) {
      return;
    }
    state.last.set(refId, { ts, severity });
    /** @type {any} */
    const alert = {
      id: `al${(this._alertSeq = (this._alertSeq || 0) + 1)}`,
      kind: hard ? 'hard-rule' : kind === 'campaign' ? 'campaign' : 'incident',
      refId,
      device: deviceId,
      severity,
      summary: incident ? incident.summary || '' : anomaly ? String(anomaly.actual) : '',
      anomalyIds: incident ? incident.anomalyIds.slice() : anomaly ? [anomaly.id] : [],
      ts,
    };
    if (incident && typeof incident.posterior === 'number') alert.posterior = incident.posterior;
    if (incident && typeof incident.score === 'number') alert.score = incident.score;
    if (kind === 'template' && this._lastTemplateId) alert.template = this._lastTemplateId;
    if (!templateAlert) state.count += 1;
    if (!templateAlert && state.count > 3 && !hard && !critical) {
      state.digest.push(alert);
      this._alertState.set(deviceId, state);
      return;
    }
    this._alertState.set(deviceId, state);
    this.emit('alert', alert);
  },

  /**
   * Fold a pending digest when the watermark crosses a UTC day and no later alert arrives.
   * @this {any}
   * @param {number} ts
   * @returns {void}
   */
  _closeAlertDays(ts) {
    if (!this.opts.alerts || !this._alertState) return;
    const day = Math.floor(ts / DAY);
    for (const [deviceId, state] of this._alertState) {
      if (state.day == null || state.day === day || state.digest.length === 0) continue;
      this.emit('alert', digestOf(deviceId, state));
      state.day = day;
      state.count = 0;
      state.digest = [];
    }
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} anomaly
   * @returns {void}
   */
  _advanceTemplates(device, anomaly) {
    if (!this._templates || anomaly.context) return;
    const matches = advance(this._templates, {
      detector: anomaly.detector,
      device: device.id,
      ts: anomaly.ts,
      id: anomaly.id,
      severity: anomaly.severity,
      shadow: anomaly.shadow === true,
      campaignId: device._campaignId,
    });
    for (const match of matches) {
      if (match.shadow) {
        if (!this._templateStats) this._templateStats = { shadow: 0, live: 0 };
        this._templateStats.shadow += 1;
        continue;
      }
      this.emit('template-match', {
        templateId: match.templateId,
        device: match.device,
        anomalyIds: match.anomalyIds,
        ts: match.ts,
      });
      if (device.incident && this.opts.scoring === 'lr') {
        device.incident.llrBonus = (device.incident.llrBonus || 0) + match.llrBonus;
        this._posterior(device.incident, anomaly.ts);
      } else if (device.incident && rankOf(device.incident.severity) < RANK.high) {
        device.incident.severity = 'high';
        this.emit('incident', incidentPayload(device.incident));
      }
      this._lastTemplateId = match.templateId;
      this._considerAlert(device, device.incident, anomaly, 'template');
    }
  },

  /**
   * @this {any}
   * @param {any} raw
   * @returns {void}
   */
  _restorePartG(raw) {
    if (!raw || typeof raw !== 'object') return;
    if (raw.annotations != null) this._annBook = annotations.fromJSON(raw.annotations);
    if (raw.criticality && typeof raw.criticality === 'object' && !Array.isArray(raw.criticality)) {
      this._criticality = new Map();
      for (const [id, level] of Object.entries(raw.criticality)) {
        if (LEVELS.has(level)) this._criticality.set(id, level);
      }
    }
    if (raw.audit != null) {
      this._audit = audit.createAuditLog();
      audit.fromJSON(this._audit, raw.audit);
      if (typeof this._audit.key === 'string') this._auditKey = this._audit.key;
      const check = audit.verifyAudit(this._audit);
      if (!check.ok) {
        this._warn('AUDIT_BROKEN', 'audit chain does not verify', null, {
          brokenAt: check.brokenAt,
        });
      }
    }
  },

  /**
   * @this {any}
   * @param {string} anomalyId
   * @returns {any}
   */
  _incidentContributions(anomalyId) {
    const key = String(anomalyId);
    for (const device of this.devices.values()) {
      const incident = device.incident;
      if (!incident || incident.id !== key || !Array.isArray(incident.contrib)) continue;
      const contributions = incident.contrib
        .map((/** @type {any} */ row) => ({
          detector: row.detector,
          llr: row.llr,
          anomalyId: row.anomalyId,
        }))
        .sort(
          (/** @type {any} */ a, /** @type {any} */ b) =>
            b.llr - a.llr || String(a.detector).localeCompare(String(b.detector)),
        );
      return { id: incident.id, contributions };
    }
    return null;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} event
   * @returns {void}
   */
  _notePeer(device, event) {
    if (!this.opts.peerSuggest) return;
    const day = Math.floor(event.ts / DAY);
    if (this._peerDay == null) this._peerDay = day;
    else if (day !== this._peerDay) {
      this._suggestPeers(event.ts);
      this._peerDay = day;
    }
    if (device.mode !== 'learning') return;
    /** @type {string[]} */
    const tokens = [];
    if (event.type === 'dns' && event.qname) {
      const family = domainFamily(String(event.qname));
      if (family) tokens.push(family);
    }
    const named = event.dstName || event.qname || event.dst;
    if (typeof named === 'string' && /[a-z]/i.test(named)) {
      const family = domainFamily(named);
      if (family) tokens.push(family);
      const full = named.toLowerCase();
      if (full !== family && full.includes('.')) tokens.push(full);
    }
    if (event.type === 'flow' && typeof event.dstPort === 'number') {
      tokens.push(`port:${event.dstPort}`);
    }
    if (tokens.length === 0) return;
    if (!device._peer) device._peer = createMinHash();
    for (const token of tokens) add(device._peer, token);
  },

  /**
   * @this {any}
   * @param {number} ts
   * @returns {void}
   */
  _suggestPeers(ts) {
    if (!this.opts.peerSuggest) return;
    /** @type {{ id: string, sig: { sig: Uint32Array } }[]} */
    const rows = [];
    for (const device of this.devices.values()) {
      if (device._peer && signatureUsed(device._peer))
        rows.push({ id: device.id, sig: device._peer });
    }
    const parent = rows.map((_, i) => i);
    const find = (/** @type {number} */ i) => {
      let x = i;
      while (parent[x] !== x) x = parent[x];
      return x;
    };
    /** @type {Map<string, number[]>} */
    const buckets = new Map();
    for (let i = 0; i < rows.length; i += 1) {
      const parts = bands(rows[i].sig);
      for (let band = 0; band < parts.length; band += 1) {
        const slice = parts[band];
        const key = `${band}:${Buffer.from(slice.buffer, slice.byteOffset, slice.byteLength).toString('hex')}`;
        const list = buckets.get(key) || [];
        list.push(i);
        buckets.set(key, list);
      }
    }
    /** @type {Set<string>} */
    const seen = new Set();
    for (const list of buckets.values()) {
      for (let a = 0; a < list.length; a += 1) {
        for (let b = a + 1; b < list.length; b += 1) {
          const i = list[a];
          const j = list[b];
          const pair = i < j ? `${i}:${j}` : `${j}:${i}`;
          if (seen.has(pair)) continue;
          seen.add(pair);
          if (jaccard(rows[i].sig, rows[j].sig) >= 0.6) parent[find(j)] = find(i);
        }
      }
    }
    /** @type {Map<number, string[]>} */
    const groups = new Map();
    for (let i = 0; i < rows.length; i += 1) {
      const root = find(i);
      const list = groups.get(root) || [];
      list.push(rows[i].id);
      groups.set(root, list);
    }
    /** @type {{ groupId: string, devices: string[], meanJaccard: number }[]} */
    const suggestions = [];
    if (!this._suggested) this._suggested = new Set();
    for (const devices of groups.values()) {
      if (devices.length < 3) continue;
      devices.sort();
      const groupId = devices.join(',');
      let total = 0;
      let n = 0;
      for (let a = 0; a < devices.length; a += 1) {
        for (let b = a + 1; b < devices.length; b += 1) {
          const left = rows.find((row) => row.id === devices[a]);
          const right = rows.find((row) => row.id === devices[b]);
          if (left && right) {
            total += jaccard(left.sig, right.sig);
            n += 1;
          }
        }
      }
      const meanJaccard = n === 0 ? 0 : total / n;
      suggestions.push({ groupId, devices, meanJaccard });
      if (!this._suggested.has(groupId)) {
        this._suggested.add(groupId);
        this._warn('PEER_GROUP_SUGGESTED', 'peer group suggested', null, { groupId, devices });
      }
    }
    this._peerSuggestions = suggestions;
    void ts;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} event
   * @returns {void}
   */
  _noteDrift(device, event) {
    if (!this.opts.drift) return;
    const day = Math.floor(event.ts / DAY);
    if (device._driftFrozen && device._driftLastDay != null && day <= device._driftLastDay) return;
    if (!device._drift) device._drift = drift.createDrift(device.id);
    if (!device._driftWelford) {
      device._driftWelford = {
        families: createWelford(),
        bytesOut: createWelford(),
        ports: createWelford(),
        hours: createWelford(),
      };
    }
    if (!device._driftDay) {
      device._driftDay = { day, families: new Set(), ports: new Set(), bytes: 0, hours: new Set() };
    }
    if (device._driftDay.day !== day) {
      this._flushDrift(device, device.mode === 'watching' && device._driftFrozen === true);
      device._driftDay = { day, families: new Set(), ports: new Set(), bytes: 0, hours: new Set() };
    }
    const bag = device._driftDay;
    const named = event.dstName || event.dst;
    if (typeof named === 'string' && /[a-z]/i.test(named)) {
      const family = domainFamily(named);
      if (family) bag.families.add(family);
    }
    if (typeof event.dstPort === 'number') bag.ports.add(event.dstPort);
    if (typeof event.bytesOut === 'number') bag.bytes += event.bytesOut;
    else if (typeof event.bytes === 'number' && event.direction !== 'in') bag.bytes += event.bytes;
    bag.hours.add(Math.floor(event.ts / 3600000) % 24);
  },

  /**
   * Commit the open learning day and freeze σ from that Welford.
   * @this {any}
   * @param {any} device
   * @returns {void}
   */
  _freezeDrift(device) {
    if (!this.opts.drift || device._driftFrozen) return;
    if (device._driftDay) this._flushDrift(device, false);
    const learned = device._driftWelford;
    device._driftSigma = {
      families: sigmaOf(learned && learned.families),
      bytesOut: sigmaOf(learned && learned.bytesOut),
      ports: sigmaOf(learned && learned.ports),
      hours: sigmaOf(learned && learned.hours),
    };
    device._driftLastDay = device._driftDay ? device._driftDay.day : -1;
    device._driftDay = null;
    device._driftFrozen = true;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {boolean} warn
   * @returns {void}
   */
  _flushDrift(device, warn) {
    const bag = device._driftDay;
    if (!bag || !device._drift) return;
    const samples = [
      ['families', bag.families.size],
      ['bytesOut', Math.log1p(bag.bytes)],
      ['ports', bag.ports.size],
      ['hours', bag.hours.size],
    ];
    for (const [series, value] of samples) {
      const learned = device._driftWelford && device._driftWelford[series];
      if (!device._driftFrozen && learned) pushWelford(learned, value);
      const sigma = device._driftFrozen ? device._driftSigma[series] || 0 : sigmaOf(learned);
      const hit = drift.observe(device._drift, series, value, bag.day, sigma);
      if (!warn || !hit) continue;
      const recentHigh =
        typeof device._driftHighTs === 'number' && bag.day * DAY - device._driftHighTs < 7 * DAY;
      if (recentHigh && device.incident) {
        if (!device.incident.data) device.incident.data = {};
        device.incident.data.drift = { series, direction: hit.direction };
        const body = /** @type {any} */ (incidentPayload(device.incident));
        if (this.opts.scoring === 'lr') {
          body.posterior = device.incident.posterior;
          body.contributions = (device.incident.contrib || []).map((/** @type {any} */ row) => ({
            detector: row.detector,
            llr: row.llr,
            anomalyId: row.anomalyId,
          }));
        }
        this.emit('incident', body);
      } else {
        const fired = device._driftDets ? [...device._driftDets].sort() : [];
        this._warn('BASELINE_DRIFT', 'baseline drift', device.id, {
          series,
          direction: hit.direction,
          sinceTs: bag.day * DAY,
          detectors: fired,
        });
      }
    }
    if (device._driftDets) device._driftDets.clear();
  },
};

/**
 * @param {string} name
 * @returns {number}
 */
function rankOf(name) {
  return RANK[/** @type {keyof typeof RANK} */ (name)] || 0;
}

/**
 * @param {any} anomaly
 * @returns {string}
 */
function stageOf(anomaly) {
  return anomaly.category || 'none';
}

/**
 * @param {string} deviceId
 * @param {{ digest: any[], day: number }} state
 */
function digestOf(deviceId, state) {
  const ids = [];
  for (const row of state.digest) for (const id of row.anomalyIds) ids.push(id);
  return {
    id: `digest-${deviceId}-${state.day}`,
    kind: 'digest',
    refId: deviceId,
    device: deviceId,
    severity: 'low',
    summary: `${state.digest.length} alerts folded`,
    anomalyIds: ids,
    ts: (state.day + 1) * DAY - 1,
  };
}

/**
 * Sample standard deviation. Zero until two positive-variance learning days exist.
 * @param {{ count: number, m2: number } | null | undefined} stats
 * @returns {number}
 */
function sigmaOf(stats) {
  if (!stats || stats.count < 2 || !(stats.m2 > 0)) return 0;
  return Math.sqrt(stats.m2 / (stats.count - 1));
}

/**
 * A signature that never received a token is all 0xffffffff and must not cluster.
 * @param {{ sig: Uint32Array }} state
 * @returns {boolean}
 */
function signatureUsed(state) {
  const sig = state.sig;
  for (let i = 0; i < sig.length; i += 1) {
    if (sig[i] !== 0xffffffff) return true;
  }
  return false;
}

module.exports = { partgMethods, PRIOR, ADD, POST };
