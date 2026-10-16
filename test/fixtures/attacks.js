'use strict';

/**
 * Many unique hosts in one moment. Built for fan-out.
 * @param {string} device
 * @param {number} ts
 * @param {number} count
 * @returns {{ device: string, dst: string, bytes: number, ts: number }[]}
 */
function fanout(device, ts, count) {
  /** @type {{ device: string, dst: string, bytes: number, ts: number }[]} */
  const events = [];
  for (let i = 0; i < count; i++) {
    events.push({ device, dst: `scan-${i}.example`, bytes: 60, ts: ts + i });
  }
  return events;
}

/**
 * @param {string} device
 * @param {number} ts
 * @param {number} bytes
 * @param {string} [dst]
 * @returns {{ device: string, dst: string, bytes: number, ts: number }}
 */
function volumeBurst(device, ts, bytes, dst = 'video.vendor.com') {
  return { device, dst, bytes, ts };
}

module.exports = { fanout, volumeBurst };
