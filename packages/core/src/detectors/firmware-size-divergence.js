'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const MB = 1024 * 1024;
const WINDOW = 72 * 60 * 60 * 1000;

const detector = {
  id: 'firmware-size-divergence',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low once peer groups are right (G10 helps)',
    consumes: ['flow'],
    attack: ['T1195.002'],
  },
  requires: ['T1'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { downloads: [], fired: false };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const row = download(ev);
    if (!row || dev.downloads.length >= 32) return;
    dev.downloads.push(row);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || !ctx.peerGroup) return;
    const row = download(ev);
    if (!row) return;
    dev.downloads.push(row);
    dev.downloads = dev.downloads.filter((/** @type {any} */ item) => ev.ts - item.ts <= WINDOW);
    if (dev.downloads.length > 32) dev.downloads = dev.downloads.slice(-32);
    /** @type {any[]} */
    const peers = ctx.peers();
    /** @type {number[]} */
    const sizes = [row.bytes];
    for (const peer of peers) {
      const other = ctx.peerState(peer, detector.id);
      if (!other || !Array.isArray(other.downloads)) continue;
      for (const item of other.downloads) {
        if (item.family === row.family && ev.ts - item.ts <= WINDOW) sizes.push(item.bytes);
      }
    }
    if (sizes.length < 3) return;
    const buckets = sizes.map((size) => Math.round(size / (64 * 1024)) * 64 * 1024);
    const mode = modeOf(buckets);
    const delta = Math.abs(row.bytes - mode);
    if (delta <= mode * 0.1 || delta <= 256 * 1024) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${row.bytes} bytes from ${row.family}`,
      expected: `about ${mode} bytes`,
      data: { family: row.family, bytes: row.bytes, mode },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { downloads: dev.downloads, fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.downloads = [];
    dev.fired = Boolean(state && state.fired);
    if (!state || !Array.isArray(state.downloads)) return;
    if (state.downloads.length > 32)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array downloads exceeds cap');
    dev.downloads = state.downloads;
  },

  memoryEstimate() {
    return 64;
  },
};

/**
 * @param {any} ev
 * @returns {{ ts: number, family: string, bytes: number } | null}
 */
function download(ev) {
  if (!ev || ev.type !== 'flow' || ev.direction !== 'in') return null;
  if (typeof ev.bytesIn !== 'number' || ev.bytesIn < MB) return null;
  const family = domainFamily(ev.dstName || ev.dst);
  if (!family) return null;
  return { ts: ev.ts, family, bytes: ev.bytesIn };
}

/**
 * @param {number[]} values
 * @returns {number}
 */
function modeOf(values) {
  /** @type {Map<number, number>} */
  const counts = new Map();
  let best = values[0];
  let n = 0;
  for (const value of values) {
    const next = (counts.get(value) || 0) + 1;
    counts.set(value, next);
    if (next > n) {
      n = next;
      best = value;
    }
  }
  return best;
}

module.exports = detector;
