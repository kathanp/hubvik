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
 */
class SampleRing {
  /**
   * @param {number} max
   */
  constructor(max) {
    if (!Number.isInteger(max) || max < 1) throw new TypeError('cap must be a positive integer');
    this.max = max;
    /** @type {number[]} */
    this.data = [];
    this.head = 0;
    this.full = false;
  }

  /** @returns {number} */
  get length() {
    return this.data.length;
  }

  /**
   * @param {number} value
   * @returns {void}
   */
  push(value) {
    if (!this.full) {
      this.data.push(value);
      if (this.data.length === this.max) this.full = true;
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
    const out = new Array(this.length);
    for (let i = 0; i < out.length; i++) out[i] = this.at(i);
    return out;
  }
}

module.exports = { LruSet, SampleRing };
