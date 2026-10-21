'use strict';

const { HubvikError } = require('../errors');

const { validateEvent } = require('./validate');
const { windowStart } = require('./window');
const { noteIdentity, rekeyIdentity } = require('./identity');
const { noteLearning, mark } = require('./learning');
const { noteWatch } = require('./promote');
const { noteHorizon } = require('./horizon');
const { noteGraph } = require('./graph');

/**
 * Validate, reorder, and dispatch one event.
 * Installed on Engine.prototype. Behavior is unchanged.
 */

module.exports = {
  /**
   * @this {any}
   * Record one event. Synchronous. Listener failures become `warning` events.
   * @param {object} raw
   * @returns {void}
   */
  feed(raw) {
    this.stateSeq = (this.stateSeq || 0) + 1;
    const budget = this.opts.budget;
    const started = budget ? budget.clock() : null;
    this._notePromotions();
    const event = this._prepare(raw);
    if (this._reorder) this._acceptReorder(event);
    else this._apply(event);
    if (budget) this._budgetAccount(budget.clock() - started);
  },

  /**
   * @this {any}
   * Validate and count one event. Does not deliver it to detectors.
   * @param {object} raw
   * @returns {any}
   */
  _prepare(raw) {
    const { event, warnings } = validateEvent(raw);
    if (event.type === 'flow') {
      if (!event.dst) event.dst = event.dstName || event.dstIp;
      if (event.bytes == null) event.bytes = (event.bytesOut || 0) + (event.bytesIn || 0);
    }
    /** @type {any} */ (this)._internEvent(event);
    this.eventsIn += 1;
    for (const warning of warnings) this._warn(warning.code, warning.message, event.device);
    if (this.startedAt == null) this.startedAt = event.ts;
    return event;
  },

  /**
   * @this {any}
   * Deliver one event to detectors. `reorderMs: 0` does this inside `feed`.
   * @param {any} event
   * @returns {void}
   */
  _apply(event) {
    noteIdentity(this, event);
    rekeyIdentity(this, event);
    const device = this._touch(event.device, event.ts);
    if (!device) return;
    const reorder = this.opts.reorderMs;
    const start = windowStart(event.ts, this.opts.windowMs);
    const inOpen =
      device.open != null && event.ts >= device.open.start && event.ts < device.open.end;
    if (!inOpen && /** @type {any} */ (this)._rejectedTime(device, event, reorder)) return;
    if (this.watermark == null || event.ts > this.watermark) this.watermark = event.ts;
    this.lastEventTs = this.watermark;
    device.lastTs = event.ts;
    /** @type {any} */ (this)._advanceTo(device, start);
    /** @type {any} */ (this)._note(device, event);
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
    if (this.opts.classSuggest) this._noteClass(device, event);
    device.dirtySeq = this.stateSeq || 0;
    this._tierNeverSeen(event.ts);
  },

  /**
   * @this {any}
   * Hold an event until event time has moved `reorderMs` past it.
   * @param {any} event
   * @returns {void}
   */
  _acceptReorder(event) {
    if (this._reorderLate(event)) return;
    const buffer = this._reorder;
    if (!buffer) return;
    this._reorderSeq += 1;
    const row = { seq: this._reorderSeq, event };
    if (buffer.length >= this.opts.maxBuffered) {
      const head = buffer[0];
      this._noteReorderOverflow(event);
      if (event.ts < head.event.ts) {
        this._noteReorderHigh(event);
        this._apply(event);
        this._releaseReorder(/** @type {number} */ (this.watermark) - this.opts.reorderMs);
        return;
      }
      buffer.shift();
      this._apply(head.event);
    }
    let lo = 0;
    let hi = buffer.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      const other = buffer[mid];
      if (other.event.ts < event.ts || (other.event.ts === event.ts && other.seq < row.seq)) {
        lo = mid + 1;
      } else hi = mid;
    }
    buffer.splice(lo, 0, row);
    this._noteReorderHigh(event);
    this._releaseReorder(/** @type {number} */ (this.watermark) - this.opts.reorderMs);
  },

  /**
   * @this {any}
   * @param {any} event
   * @returns {void}
   */
  _noteReorderHigh(event) {
    const prev = this._reorderHigh.get(event.device);
    if (prev == null || event.ts > prev) this._reorderHigh.set(event.device, event.ts);
    if (this.watermark == null || event.ts > this.watermark) this.watermark = event.ts;
    this.lastEventTs = this.watermark;
  },

  /**
   * @this {any}
   * @param {any} event
   * @returns {void}
   */
  _noteReorderOverflow(event) {
    const minute = Math.floor(event.ts / 60_000);
    if (this._reorderOverflowMinute === minute) return;
    this._reorderOverflowMinute = minute;
    this._warn('REORDER_OVERFLOW', 'reorder buffer released the oldest event', event.device);
  },

  /**
   * @this {any}
   * Drop an event that is already behind the release limit or a sealed window.
   * @param {any} event
   * @returns {boolean}
   */
  _reorderLate(event) {
    const reorder = this.opts.reorderMs;
    const device = this.devices.get(event.device);
    const inOpen =
      device && device.open != null && event.ts >= device.open.start && event.ts < device.open.end;
    if (
      !inOpen &&
      device &&
      device.seen &&
      /** @type {any} */ (this)._rejectedTime(device, event, reorder)
    )
      return true;
    const high = this._reorderHigh.get(event.device);
    const behindDevice = high != null && event.ts < high - reorder;
    const behindWatermark = this.watermark != null && event.ts < this.watermark - reorder;
    if (!behindDevice && !behindWatermark) return false;
    if (behindDevice) {
      const holder = device && device.seen ? device : this._touch(event.device, event.ts);
      if (holder) {
        this._warn('CLOCK_JUMP', 'timestamp moved backward', event.device);
        this._clockJump(holder, event);
      }
    }
    this._warn('LATE_EVENT', 'event is older than an open window', event.device);
    return true;
  },

  /**
   * @this {any}
   * Deliver buffered events whose timestamp is at or before `limit`.
   * @param {number} limit
   * @returns {void}
   */
  _releaseReorder(limit) {
    const buffer = this._reorder;
    if (!buffer) return;
    while (buffer.length > 0 && buffer[0].event.ts <= limit) {
      const row = buffer.shift();
      if (row) this._apply(row.event);
    }
  },

  /**
   * @this {any}
   * Feed a batch after sorting it by timestamp. Does not mutate the input array.
   * @param {any[]} events
   * @returns {void}
   */
  feedBatch(events) {
    if (!Array.isArray(events))
      throw new HubvikError('EVENTS_MUST_BE_AN_ARRAY', 'events must be an array');
    const copy = events.slice().sort((a, b) => (a && a.ts ? a.ts : 0) - (b && b.ts ? b.ts : 0));
    for (const event of copy) this.feed(event);
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} event
   */
  _run(device, event) {
    if (this._horizonOn) noteHorizon(device, event);
    if (this._graphOn) noteGraph(this, device, event);
    if (typeof this._notePeer === 'function') this._notePeer(device, event);
    if (typeof this._noteDrift === 'function') this._noteDrift(device, event);
    const learning = device.mode === 'learning';
    const ctx = this._ctx(device, learning, event.ts);
    ctx.window = device.open;
    const list = this.byType[event.type] || [];
    for (const det of list) {
      if (this._sheds(det)) {
        if (learning && !this._shedLearn && !det.hardRule && typeof det.learn === 'function') {
          det.learn(/** @type {any} */ (this)._state(device, det), event, ctx);
        } else if (learning && this._shedLearn) device.shedLearn = true;
        continue;
      }
      const state = /** @type {any} */ (this)._state(device, det);
      ctx.options = /** @type {any} */ (this)._optionsFor(det);
      if (learning && !det.hardRule) {
        if (typeof det.learn === 'function') {
          const noted = det.learn(state, event, ctx);
          if (noted && typeof noted.reason === 'string') {
            mark(this, device, event, noted.reason, noted.message || noted.reason);
          } else if (noted && typeof noted.severity === 'string') {
            this._take(device, det, noted, learning, event);
          }
        }
      } else if (typeof det.check === 'function') {
        this._take(device, det, det.check(state, event, ctx), learning, event);
      }
      const canary = this._canaryOverrides(det);
      if (canary) {
        const saved = ctx.options;
        ctx.options = { ...saved, ...canary };
        const copy = this._canaryState(device, det);
        if (learning && !det.hardRule) {
          if (typeof det.learn === 'function') det.learn(copy, event, ctx);
        } else if (typeof det.check === 'function') {
          this._take(device, det, det.check(copy, event, ctx), learning, event, 'canary');
        }
        ctx.options = saved;
      }
    }
    if (this.opts.promote && device.mode === 'watching') noteWatch(this, device, event);
  },
};
