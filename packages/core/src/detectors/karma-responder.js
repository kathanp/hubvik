'use strict';

const { HubvikError } = require('../errors');

const { scratchBag } = require('./lib');
const { assertState } = require('./state');

const CAP = 256;

const detector = {
  id: 'karma-responder',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Low. Real APs answer for the SSIDs they host, usually 1–4',
    consumes: ['wifi'],
    attack: ['T1557'],
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || ev.type !== 'wifi' || ev.op !== 'probe-resp' || !ev.bssid || !ev.ssid) return;
    const own = ctx.ownBssids || [];
    if (own.includes(ev.bssid)) return;
    const start = ctx.window && ctx.window.start;
    const bag = scratchBag(ctx, 'karma-responder', () => ({ win: start, rows: new Map() }));
    if (bag.win !== start) {
      bag.win = start;
      bag.rows = new Map();
    }
    let ssids = bag.rows.get(ev.bssid);
    if (!ssids) {
      if (bag.rows.size >= CAP) {
        const oldest = bag.rows.keys().next().value;
        if (oldest !== undefined) bag.rows.delete(oldest);
      }
      ssids = new Set();
      bag.rows.set(ev.bssid, ssids);
    }
    if (ssids.size < 32) ssids.add(ev.ssid);
    if (ssids.size < 5) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.bssid} answered ${ssids.size} SSIDs`,
      expected: 'probe responses for fewer than 5 SSIDs',
      data: { bssid: ev.bssid, ssids: [...ssids] },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.fired = Boolean(state && state.fired);
    if (state && state.extra && Array.isArray(state.extra) && state.extra.length > CAP) {
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array extra exceeds cap');
    }
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
