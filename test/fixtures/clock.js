'use strict';

/** Monday 5 Jan 2026 00:00 UTC. Stable origin for every fixture. */
const T0 = Date.UTC(2026, 0, 5, 0, 0, 0);
const H = 3600e3;
const DAY = 24 * H;

/**
 * @param {number} day
 * @param {number} hour
 * @param {number} [min]
 * @param {number} [sec]
 * @returns {number}
 */
function at(day, hour, min = 0, sec = 0) {
  return T0 + day * DAY + hour * H + min * 60e3 + sec * 1000;
}

module.exports = { T0, H, DAY, at };
