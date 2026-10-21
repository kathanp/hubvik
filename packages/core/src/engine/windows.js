'use strict';

const { HubvikError } = require('../errors');

const { isGroupDst } = require('../detectors/lib');
const { planClose } = require('./window');
const { rollHorizon } = require('./horizon');

/**
 * Window close, flush, and tick.
 * Installed on Engine.prototype. Behavior is unchanged.
 */

module.exports = {
  /**
   * @this {any}
   * No argument drains every open window whose start is <= the watermark.
   * An explicit now closes only windows whose end is <= now.
   * @param {number} [now]
   * @returns {void}
   */
  flush(now) {
    const explicit = arguments.length > 0 && now !== undefined;
    if (explicit && (typeof now !== 'number' || !Number.isFinite(now))) {
      throw new HubvikError('FLUSH_TIME_IS_INVALID', 'flush time is invalid');
    }
    if (!explicit) {
      this._releaseReorder(Infinity);
      this._drain();
      this.tick();
      return;
    }
    this._releaseReorder(now);
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
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
   * Run time-based checks at now, or at the watermark when now is omitted.
   * @param {number} [now]
   * @returns {void}
   */
  tick(now) {
    this._notePromotions();
    const at = now === undefined ? this.watermark : now;
    if (at == null) return;
    if (typeof at !== 'number' || !Number.isFinite(at))
      throw new HubvikError('TICK_TIME_IS_INVALID', 'tick time is invalid');
    this._releaseReorder(at);
    const det = this.byId.get('went-silent');
    const status = this.detectorStatus['went-silent'];
    if (det && status && status.active && typeof det.tick === 'function') {
      for (const device of this.devices.values()) {
        if (!device.seen || device.mode !== 'watching') continue;
        const ctx = this._ctx(device, false, at);
        ctx.options = /** @type {any} */ (this)._optionsFor(det);
        this._take(
          device,
          det,
          det.tick(/** @type {any} */ (this)._state(device, det), ctx),
          false,
          null,
        );
      }
    }
    this._inputGap(at);
    this._tierSilent(at);
    this._tierNeverSeen(at);
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {number} start
   */
  _advanceTo(device, start) {
    if (device.open && start < device.open.end) return;
    if (!device.open && device.cursor == null) {
      device.open = this._borrow(device, 'open', start);
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
    device.open = this._borrow(device, 'open', start);
    device.cursor = start;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {{ closeOpen: boolean, idles: number[], cursor: number | null }} plan
   */
  _applyPlan(device, plan) {
    if (plan.closeOpen && device.open) this._finalize(device, device.open);
    for (const start of plan.idles) this._finalize(device, this._borrow(device, 'idle', start));
    if (plan.closeOpen || plan.idles.length > 0) {
      if (device.open) device.pool = device.open;
      device.open = null;
      device.cursor = plan.cursor;
    }
  },

  /**
   * @this {any}
   * Reuse one open window and one idle window per device. A feed that arrives
   * while a window is closing gets a fresh object so the close stays stable.
   * @param {any} device
   * @param {'open' | 'idle'} kind
   * @param {number} start
   * @returns {any}
   */
  _borrow(device, kind, start) {
    if (device.closing) return this._window(start);
    const slot = kind === 'open' ? device.pool : device.idlePool;
    if (!slot || !slot.dstSet) {
      const fresh = this._window(start);
      if (kind === 'open') device.pool = fresh;
      else device.idlePool = fresh;
      return fresh;
    }
    return this._resetWindow(slot, start);
  },

  /**
   * @this {any}
   * @param {any} win
   * @param {number} start
   * @returns {any}
   */
  _resetWindow(win, start) {
    win.start = start;
    win.end = start + this.opts.windowMs;
    win.bytes = 0;
    win.dstCount = 0;
    win.dstSet.clear();
    win.saturated = false;
    win.fanoutAlerted = false;
    win.events = 0;
    win.newDst = 0;
    win.newFamilies = 0;
    win.idle = false;
    if (win.egressDsts) win.egressDsts.clear();
    return win;
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} event
   */
  _note(device, event) {
    if (!device.open) return;
    device.open.events = (device.open.events || 0) + 1;
    device.open.bytes += event.bytes || 0;
    if (!event.dst || isGroupDst(event.dst)) return;
    const win = device.open;
    if (win.dstSet.has(event.dst)) return;
    if (win.fanoutAlerted || win.dstSet.size >= this.opts.maxWindowDestinations) {
      win.dstCount += 1;
      win.saturated = true;
      return;
    }
    win.dstSet.add(event.dst);
    win.dstCount = win.dstSet.size;
  },

  /**
   * @this {any}
   * @param {any} device
   * @param {any} win
   */
  _finalize(device, win) {
    if (this._horizonOn) rollHorizon(device, win.start);
    const learning =
      !device.frozen &&
      device.learnStart != null &&
      win.start < device.learnStart + this.opts.learnMs;
    const summary = device.summary || (device.summary = {});
    summary.start = win.start;
    summary.end = win.end;
    summary.bytes = win.bytes;
    summary.dstCount = win.dstCount;
    summary.fanoutAlerted = win.fanoutAlerted;
    summary.newDst = win.newDst;
    summary.idle = win.bytes === 0 && win.dstCount === 0;
    const ctx = this._ctx(device, learning, summary.start);
    ctx.window = summary;
    ctx.lanInDegree = device.lanPeers ? device.lanPeers.size : 0;
    device.closing = (device.closing || 0) + 1;
    try {
      for (const det of this.active) {
        if (typeof det.onWindowClose !== 'function') continue;
        ctx.options = /** @type {any} */ (this)._optionsFor(det);
        const draft = det.onWindowClose(
          /** @type {any} */ (this)._state(device, det),
          summary,
          ctx,
        );
        this._take(device, det, draft, learning, null);
        const canary = this._canaryOverrides(det);
        if (canary) {
          const saved = ctx.options;
          ctx.options = { ...saved, ...canary };
          const copy = det.onWindowClose(this._canaryState(device, det), summary, ctx);
          this._take(device, det, copy, learning, null, 'canary');
          ctx.options = saved;
        }
      }
    } finally {
      device.closing -= 1;
    }
    this._tallyCanaries(device);
    if (device.lanPeers) device.lanPeers = new Set();
    if (win.dstSet) win.dstSet.clear();
    if (win.egressDsts) win.egressDsts.clear();
  },
};
