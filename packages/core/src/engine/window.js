'use strict';

/**
 * Epoch-aligned window start containing `ts`.
 * @param {number} ts
 * @param {number} windowMs
 * @returns {number}
 */
function windowStart(ts, windowMs) {
  const mod = ts % windowMs;
  return mod === 0 ? ts : ts - mod;
}

/**
 * Plan which open window and which following idle windows have ended by `until`.
 * Idle steps are capped so a multi-month gap cannot allocate one window per minute.
 * @param {number | null} cursor Start of the next window that has not been closed.
 * @param {{ start: number, end: number } | null} open
 * @param {number} until Close windows whose end is <= until.
 * @param {number} windowMs
 * @param {number} maxIdle
 * @returns {{ closeOpen: boolean, idles: number[], cursor: number | null }}
 */
function planClose(cursor, open, until, windowMs, maxIdle) {
  if (open && open.end > until) return { closeOpen: false, idles: [], cursor };
  let next = cursor;
  const closeOpen = Boolean(open);
  if (open) next = open.end;
  if (next == null || next >= until) return { closeOpen, idles: [], cursor: next };
  let steps = Math.floor((until - next) / windowMs);
  if (steps > maxIdle) {
    next += (steps - maxIdle) * windowMs;
    steps = maxIdle;
  }
  const idles = new Array(steps);
  for (let i = 0; i < steps; i++) {
    idles[i] = next;
    next += windowMs;
  }
  return { closeOpen, idles, cursor: next };
}

module.exports = { windowStart, planClose };
