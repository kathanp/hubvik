'use strict';

/** @type {Record<string, string[]>} */
const ROOT_KEYS = {
  'volume-spike': ['sigma', 'minBytes', 'peakFactor'],
  'fan-out': ['minFanout', 'fanoutFactor'],
  'new-destination': ['maxNewDstPerWindow'],
};

/**
 * Device records, caps, and the per-detector options overlay.
 * Installed on Engine.prototype. Behavior is unchanged.
 */

module.exports = {
  /**
   * @this {any}
   * @returns {any}
   */
  _caps() {
    return this.opts;
  },

  /**
   * @this {any}
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
        if (key === 'enabled' || key === 'mode' || key === 'canary') continue;
        options[key] = value;
      }
    }
    return options;
  },

  /**
   * @this {any}
   * One string object per destination text, up to the existing destination cap.
   * @param {string} value
   * @returns {string}
   */
  _intern(value) {
    const hit = this.names.get(value);
    if (hit !== undefined) return hit;
    if (this.names.size >= this.opts.maxDestinations) return value;
    this.names.set(value, value);
    return value;
  },

  /**
   * @this {any}
   * @param {any} event
   * @returns {void}
   */
  _internEvent(event) {
    for (const key of ['dst', 'dstIp', 'dstName', 'qname', 'sni']) {
      const value = event[key];
      if (typeof value === 'string' && value.length > 0) event[key] = this._intern(value);
    }
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
   * @param {any} det
   */
  _freshState(det) {
    return typeof det.createState === 'function' ? det.createState(this._caps()) : {};
  },

  /**
   * @this {any}
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
  },

  /**
   * @this {any}
   * @param {string} id
   */
  _requireDevice(id) {
    const device = this.devices.get(id);
    if (!device || !device.seen) throw new TypeError(`unknown device ${id}`);
    return device;
  },
};
