'use strict';
/**
 * CyberShield engine v0 — per-device network baselines.
 *
 * Feed it connection summaries from a gateway (DNS logs, conntrack, flows):
 *   engine.feed({ device: 'aa:bb:cc:dd:ee:ff', dst: 'api.vendor.com', bytes: 512, ts: Date.now() })
 *
 * Learn mode: each device learns its own normal for `learnMs`.
 * Watch mode: emits 'anomaly' events. It never blocks anything itself;
 * the host product decides the action.
 *
 * Detectors (v0): new-destination, fan-out, volume-spike, wrong-time.
 */
const { EventEmitter } = require('node:events');

function summarize(values) {
  const n = values.length;
  if (n === 0) return { n: 0, mean: 0, std: 0, max: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / n;
  const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / n;
  return { n, mean, std: Math.sqrt(variance), max: Math.max(...values) };
}

class Engine extends EventEmitter {
  constructor(opts = {}) {
    super();
    this.learnMs = opts.learnMs ?? 7 * 24 * 3600e3; // 7 days
    this.windowMs = opts.windowMs ?? 60e3;          // 1-minute windows
    this.sigma = opts.sigma ?? 4;                   // volume spike sensitivity
    this.minFanout = opts.minFanout ?? 10;          // never alert below this many hosts/window
    this.minBytes = opts.minBytes ?? 1e6;           // never alert below 1 MB/window
    this.maxNewDstPerWindow = opts.maxNewDstPerWindow ?? 3; // cap alert floods
    this.hourOf = opts.hourOf ?? ((ts) => new Date(ts).getUTCHours()); // pass a local-time fn if needed
    this.devices = new Map();
  }

  _device(id, ts) {
    let d = this.devices.get(id);
    if (!d) {
      d = {
        id, firstSeen: ts, locked: false,
        dsts: new Set(), hours: new Set(),
        winBytes: [], winFanout: [],
        cur: null, alerted: new Set(),
      };
      this.devices.set(id, d);
    }
    return d;
  }

  _learning(d, ts) {
    return !d.locked && ts - d.firstSeen < this.learnMs;
  }

  feed(ev) {
    if (!ev || !ev.device) throw new TypeError('event.device is required');
    const ts = ev.ts ?? Date.now();
    const d = this._device(ev.device, ts);

    const start = ts - (ts % this.windowMs);
    if (d.cur && d.cur.start !== start) this._closeWindow(d);
    if (!d.cur) d.cur = { start, bytes: 0, dsts: new Set(), fanoutAlerted: false };
    d.cur.bytes += ev.bytes || 0;
    if (ev.dst) d.cur.dsts.add(ev.dst);

    const hour = this.hourOf(ts);

    if (this._learning(d, ts)) {
      if (ev.dst) d.dsts.add(ev.dst);
      d.hours.add(hour);
      return;
    }
    d.locked = true;

    // 1. New destination (alerted once; never added to the baseline automatically).
    // Capped per window so a scan produces one fan-out alert, not hundreds of these.
    if (ev.dst && !d.dsts.has(ev.dst) && !d.alerted.has('dst:' + ev.dst)) {
      d.alerted.add('dst:' + ev.dst);
      d.cur.newDst = (d.cur.newDst || 0) + 1;
      if (d.cur.newDst <= this.maxNewDstPerWindow) {
        this._emit(d, 'new-destination', ts, 'medium', ev.dst, `${d.dsts.size} known hosts`);
      }
    }

    // 2. Fan-out: too many unique hosts in one window (scanning / DDoS)
    const fan = summarize(d.winFanout);
    const fanLimit = Math.max(this.minFanout, fan.max * 3);
    if (!d.cur.fanoutAlerted && d.cur.dsts.size > fanLimit) {
      d.cur.fanoutAlerted = true;
      this._emit(d, 'fan-out', ts, 'high', `${d.cur.dsts.size} hosts/window`, `<= ${fanLimit}`);
    }

    // 3. Wrong time: activity in an hour the device was never active during learning
    const dayKey = `hour:${Math.floor(ts / 86400e3)}:${hour}`;
    if (!d.hours.has(hour) && !d.alerted.has(dayKey)) {
      d.alerted.add(dayKey);
      this._emit(d, 'wrong-time', ts, 'low', `active at hour ${hour}`, `hours ${[...d.hours].sort((a, b) => a - b).join(',')}`);
    }
  }

  _closeWindow(d) {
    const w = d.cur;
    d.cur = null;
    if (!w) return;
    if (!d.locked && w.start - d.firstSeen < this.learnMs) {
      d.winBytes.push(w.bytes);
      d.winFanout.push(w.dsts.size);
      return;
    }
    // 4. Volume spike, checked when a window closes
    const s = summarize(d.winBytes);
    const limit = Math.max(this.minBytes, s.mean + this.sigma * s.std, s.max * 2);
    if (w.bytes > limit) {
      this._emit(d, 'volume-spike', w.start, 'high', `${w.bytes} bytes/window`, `<= ${Math.round(limit)}`);
    }
  }

  /** Close open windows (call on a timer, e.g. every windowMs). */
  flush() {
    for (const d of this.devices.values()) this._closeWindow(d);
  }

  _emit(d, detector, ts, severity, actual, expected) {
    this.emit('anomaly', { device: d.id, detector, severity, ts, actual, expected });
  }

  /** Stop learning now for all devices (e.g. after human review). */
  lock() {
    for (const d of this.devices.values()) d.locked = true;
  }

  exportBaseline() {
    const out = {};
    for (const d of this.devices.values()) {
      out[d.id] = {
        dsts: [...d.dsts],
        hours: [...d.hours],
        winBytes: d.winBytes.slice(-10080),
        winFanout: d.winFanout.slice(-10080),
      };
    }
    return { version: 1, devices: out };
  }

  importBaseline(baseline) {
    if (!baseline || baseline.version !== 1) throw new Error('unsupported baseline');
    for (const [id, b] of Object.entries(baseline.devices)) {
      const d = this._device(id, 0);
      d.dsts = new Set(b.dsts);
      d.hours = new Set(b.hours);
      d.winBytes = b.winBytes.slice();
      d.winFanout = b.winFanout.slice();
      d.locked = true;
    }
  }
}

function createEngine(opts) {
  return new Engine(opts);
}

module.exports = { createEngine, Engine };
