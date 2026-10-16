'use strict';

/**
 * mulberry32. Same seed always returns the same sequence.
 * @param {number} seed
 * @returns {() => number} Float in [0, 1).
 */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * @param {() => number} rng
 * @param {number} min
 * @param {number} max
 * @returns {number}
 */
function range(rng, min, max) {
  return min + (max - min) * rng();
}

module.exports = { mulberry32, range };
