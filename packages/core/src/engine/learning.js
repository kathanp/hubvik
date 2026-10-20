'use strict';

const { domainFamily } = require('./net');
const { median } = require('../detectors/lib');

const DAY = 24 * 3600e3;

/**
 * Learning-quality warnings. These do not become anomalies.
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 */
function noteLearning(engine, device, event) {
  if (device.mode !== 'learning' || device.learnStart == null) return;
  const families = device.learnFamilies || (device.learnFamilies = new Set());
  const family = domainFamily(event.dst);
  if (family && !families.has(family)) {
    families.add(family);
    const day = Math.floor((event.ts - device.learnStart) / DAY);
    if (day !== device.learnFamilyDay) {
      device.learnFamilyDay = day;
      device.learnFamilyNew = 0;
    }
    device.learnFamilyNew = (device.learnFamilyNew || 0) + 1;
    if (day >= 2 && device.learnFamilyNew > 20) {
      mark(
        engine,
        device,
        event,
        'family-churn',
        `${device.learnFamilyNew} new destination families on learning day ${day}`,
      );
    }
  }
  if (event.proto === 'gre' || event.proto === 47) {
    mark(engine, device, event, 'gre', 'GRE traffic during learning');
  }
  if (
    event.type === 'flow' &&
    event.direction === 'out' &&
    (event.dstPort === 23 || event.dstPort === 2323)
  ) {
    mark(engine, device, event, 'telnet-out', 'outbound telnet during learning');
  }
  if (
    event.type === 'flow' &&
    event.proto === 'tcp' &&
    (event.dstPort === 5555 || event.srcPort === 5555)
  ) {
    mark(engine, device, event, 'adb', 'TCP 5555 during learning');
  }
  if (event.type === 'dns' && String(event.rcode).toUpperCase() === 'NXDOMAIN') {
    if (device.nxWindow !== event.ts - (event.ts % engine.opts.windowMs)) {
      device.nxWindow = event.ts - (event.ts % engine.opts.windowMs);
      device.nxCount = 0;
      device.nxWarned = false;
    }
    device.nxCount += 1;
    if (device.nxCount >= 10) {
      mark(engine, device, event, 'nxdomain-burst', 'NXDOMAIN burst during learning');
    }
  }
  noteLateFamily(engine, device, family, event);
  noteRamp(engine, device, event);
  noteBeacon(engine, device, event);
  proxyShape(engine, device, event);
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @param {string} reason
 * @param {string} message
 */
function mark(engine, device, event, reason, message) {
  const reasons = device.suspicious || (device.suspicious = []);
  if (reasons.includes(reason)) return;
  reasons.push(reason);
  engine._warn('SUSPICIOUS_LEARNING', message, device.id, { reason, ts: event.ts });
}

/**
 * More than half of the learned families first appear in the last 10% of learning.
 * @param {any} engine
 * @param {any} device
 * @param {string | null} family
 * @param {any} event
 * @returns {void}
 */
function noteLateFamily(engine, device, family, event) {
  const span = engine.opts.learnMs;
  if (!family || !(span > 0)) return;
  const first = device.familyFirst || (device.familyFirst = new Map());
  if (first.has(family)) return;
  if (first.size >= engine.opts.maxDestinations) return;
  first.set(family, event.ts);
  const cut = device.learnStart + span * 0.9;
  let late = 0;
  for (const seen of first.values()) {
    if (seen >= cut) late += 1;
  }
  if (late * 2 > first.size) {
    mark(
      engine,
      device,
      event,
      'late-family-burst',
      'most learned families appeared in the last 10% of learning',
    );
  }
}

/**
 * Last-third windows average more than three times the first-third windows.
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @returns {void}
 */
function noteRamp(engine, device, event) {
  const span = engine.opts.learnMs;
  if (!(span > 0)) return;
  const offset = event.ts - device.learnStart;
  if (offset < 0 || offset >= span) return;
  const third = span / 3;
  /** @type {'rampFirst' | 'rampLast' | null} */
  let key = null;
  if (offset < third) key = 'rampFirst';
  else if (offset >= third * 2) key = 'rampLast';
  if (!key) return;
  const start = event.ts - (event.ts % engine.opts.windowMs);
  const row = device[key] || (device[key] = { windows: 0, bytes: 0, window: null });
  if (row.window !== start) {
    row.window = start;
    row.windows += 1;
  }
  row.bytes += event.bytes || 0;
  const early = device.rampFirst;
  const late = device.rampLast;
  if (!early || !late || early.windows < 100 || late.windows < 100) return;
  if (late.bytes / late.windows > (early.bytes / early.windows) * 3) {
    mark(
      engine,
      device,
      event,
      'ramp',
      'bytes per window rose more than 3× from the first third of learning to the last',
    );
  }
}

/**
 * A destination first contacted after half of learning matches the new-beacon periodicity test.
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @returns {void}
 */
function noteBeacon(engine, device, event) {
  const span = engine.opts.learnMs;
  if (!(span > 0) || event.type !== 'flow') return;
  const dst = event.dstName || event.dstIp || null;
  if (!dst) return;
  const cut = device.learnStart + span * 0.5;
  if (event.ts < cut) return;
  const tracks = device.beaconBorn || (device.beaconBorn = new Map());
  let row = tracks.get(dst);
  if (!row) {
    const det = engine.byId.get('new-beacon');
    const learned = det ? engine._state(device, det) : null;
    if (learned && learned.baseline && learned.baseline.has(dst)) return;
    if (tracks.size >= 16) return;
    row = { gaps: [], sizes: [], last: null, count: 0 };
    tracks.set(dst, row);
  }
  if (row.last != null && row.gaps.length < 32) row.gaps.push(event.ts - row.last);
  row.last = event.ts;
  const size = event.bytesOut ?? event.bytes ?? 0;
  if (row.sizes.length < 32) row.sizes.push(size);
  row.count += 1;
  if (row.count < 20 || row.gaps.length < 19) return;
  const med = median(row.gaps);
  if (!(med > 0)) return;
  const mad = median(row.gaps.map((/** @type {number} */ gap) => Math.abs(gap - med)));
  if (mad / med > 0.25) return;
  const hi = Math.max(...row.sizes);
  const lo = Math.min(...row.sizes);
  if (lo > 0 && hi / lo > 3) return;
  mark(
    engine,
    device,
    event,
    'beacon-born-in-learning',
    'a periodic destination was first contacted after half of learning',
  );
}

/**
 * @param {any} engine
 * @param {any} device
 * @param {any} event
 * @returns {void}
 */
function proxyShape(engine, device, event) {
  if ((device.suspicious || []).includes('proxy-shape')) return;
  const shadow = device.proxyShadow || (device.proxyShadow = Object.create(null));
  const ctx = engine._ctx(device, true, event.ts);
  ctx.window = device.open;
  for (const id of ['proxy-relay', 'proxy-backconnect', 'p2p-pattern']) {
    const det = engine.byId.get(id);
    if (!det) continue;
    if (!shadow[id]) shadow[id] = det.createState(engine.opts);
    ctx.options = engine._optionsFor(det);
    if (det.check(shadow[id], event, ctx)) {
      mark(engine, device, event, 'proxy-shape', 'proxy shape during learning');
      return;
    }
  }
}

const learningMethods = {
  /**
   * @this {any}
   * End learning for one device, or for every device.
   * @param {string} [deviceId]
   * @returns {void}
   */
  lock(deviceId) {
    /** @type {any} */ (this)._releaseReorder(Infinity);
    const list =
      deviceId == null
        ? [...this.devices.values()]
        : [/** @type {any} */ (this)._requireDevice(deviceId)];
    for (const device of list) {
      if (device.mode === 'learning' && device.seen) {
        if (!this._quality(device).ready) {
          this._warn('LOCKED_UNREVIEWED', 'locked before learning looked clean', device.id);
        }
        this._enterWatch(device, device.learnStart ?? 0);
      }
    }
  },

  /**
   * @this {any}
   * Clear detector baselines and learn again from the next event.
   * @param {string} deviceId
   * @param {{ detectors?: string[] }} [opts]
   * @returns {void}
   */
  relearn(deviceId, opts = {}) {
    const device = /** @type {any} */ (this)._requireDevice(deviceId);
    const ids = opts.detectors ?? this.registry.map((/** @type {any} */ det) => det.id);
    if (!Array.isArray(ids)) throw new TypeError('detectors must be an array');
    for (const id of ids) {
      const det = this.byId.get(id);
      if (!det) throw new TypeError(`unknown detector ${id}`);
      device.states.set(id, /** @type {any} */ (this)._freshState(det));
    }
    device.mode = 'learning';
    device.frozen = false;
    device.learnStart = null;
    device.open = null;
    device.cursor = null;
    device.sealedUntil = null;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {number} ts
   */
  _enterWatch(device, ts) {
    if (device.mode === 'watching') return;
    device.mode = 'watching';
    device.frozen = true;
    this.emit('learned', { device: device.id, ts });
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
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
      ready:
        suspicious.length === 0 && windowsActive >= this.opts.minLearnWindows && !device.shedLearn,
    };
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
   * One warning per enabled tier that still has no events once learning has ended.
   * @param {number} now
   */
  _tierNeverSeen(now) {
    if (typeof now !== 'number' || this.startedAt == null) return;
    if (now < this.startedAt + this.opts.learnMs) return;
    if (!this.tierNeverWarned) this.tierNeverWarned = Object.create(null);
    const seen = /** @type {any} */ (this).tierSeen || {};
    for (const tier of this.opts.tiers) {
      if (typeof seen[tier] === 'number' || this.tierNeverWarned[tier]) continue;
      this.tierNeverWarned[tier] = true;
      this._warn('TIER_NEVER_SEEN', `${tier} had no events by the end of learning`, undefined, {
        ts: now,
      });
    }
  },

  /**
   * @this {any}
   * @param {number} now
   */
  _tierSilent(now) {
    const seen = /** @type {any} */ (this).tierSeen || {};
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
          (/** @type {any} */ det) =>
            det.requires.includes(tier) &&
            this.detectorStatus[det.id] &&
            this.detectorStatus[det.id].active,
        )
        .map((/** @type {any} */ det) => det.id);
      const device = { id: 'engine', suppress: new Map(), states: new Map() };
      this._special(
        'tier-silent',
        device,
        { ts: now, device: 'engine' },
        { kind: 'tier-silent', tier, detectors },
        false,
      );
    }
  },

  /**
   * @this {any}
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
  },
};

module.exports = { noteLearning, mark, learningMethods };
