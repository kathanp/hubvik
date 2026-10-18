'use strict';

/**
 * Insertion-ordered set that forgets the oldest value past `max`.
 */
class LruSet {
  /**
   * @param {number} max
   */
  constructor(max) {
    if (!Number.isInteger(max) || max < 1) throw new TypeError('cap must be a positive integer');
    this.max = max;
    /** @type {Map<string, number>} */
    this.map = new Map();
  }

  /**
   * @param {string} value
   * @returns {boolean} True when the value was not already present.
   */
  add(value) {
    if (this.map.has(value)) {
      this.map.delete(value);
      this.map.set(value, 1);
      return false;
    }
    this.map.set(value, 1);
    if (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) this.map.delete(oldest);
    }
    return true;
  }

  /**
   * @param {string} value
   * @returns {boolean}
   */
  has(value) {
    return this.map.has(value);
  }

  /** @returns {number} */
  get size() {
    return this.map.size;
  }

  /** Oldest first. @returns {string[]} */
  toArray() {
    return [...this.map.keys()];
  }
}

/**
 * Fixed-capacity numeric history. Push is O(1). Index 0 is the oldest sample.
 * Values live in a Float64Array that grows to `max` and then rings. `toArray()`
 * still returns a plain array, so exported baselines stay JSON arrays.
 */
class SampleRing {
  /**
   * @param {number} max
   */
  constructor(max) {
    if (!Number.isInteger(max) || max < 1) throw new TypeError('cap must be a positive integer');
    this.max = max;
    /** @type {Float64Array} */
    this.data = new Float64Array(0);
    this.count = 0;
    this.head = 0;
    this.full = false;
  }

  /** @returns {number} */
  get length() {
    return this.count;
  }

  /**
   * Grow the buffer. A full ring's buffer length is exactly `max`.
   * @returns {void}
   */
  _grow() {
    const next =
      this.data.length === 0 ? Math.min(this.max, 8) : Math.min(this.max, this.data.length * 2);
    const grown = new Float64Array(next);
    if (this.data.length > 0) grown.set(this.data);
    this.data = grown;
  }

  /**
   * @param {number} value
   * @returns {void}
   */
  push(value) {
    if (!this.full) {
      if (this.count === this.data.length) this._grow();
      this.data[this.count] = value;
      this.count += 1;
      if (this.count === this.max) this.full = true;
      return;
    }
    this.data[this.head] = value;
    this.head += 1;
    if (this.head === this.max) this.head = 0;
  }

  /**
   * @param {number} index Zero is the oldest sample.
   * @returns {number}
   */
  at(index) {
    if (!this.full) return this.data[index];
    return this.data[(this.head + index) % this.max];
  }

  /** @returns {number[]} Oldest first. */
  toArray() {
    const out = new Array(this.count);
    for (let i = 0; i < this.count; i++) out[i] = this.at(i);
    return out;
  }
}

module.exports = { LruSet, SampleRing };
