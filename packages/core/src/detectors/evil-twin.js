'use strict';

const { explainNewMember } = require('./lib');

const CAP = 32;

const detector = {
  id: 'evil-twin',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: ['wifi'],
    explains: true,
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { enabled: true, severity: 'critical' },

  createState() {
    return { ssids: new Map(), clients: new Set(), fired: false };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    if (!ev || ev.op !== 'assoc' || typeof ev.ssid !== 'string' || typeof ev.bssid !== 'string')
      return;
    dev.clients.add(ev.mac);
    let set = dev.ssids.get(ev.ssid);
    if (!set) {
      set = new Set();
      dev.ssids.set(ev.ssid, set);
    }
    if (set.size < CAP) set.add(ev.bssid);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (dev.fired || !ev || ev.op !== 'assoc') return;
    if (typeof ev.ssid !== 'string' || typeof ev.bssid !== 'string') return;
    const known = dev.ssids.get(ev.ssid);
    if (!known || !dev.clients.has(ev.mac)) return;
    if (known.has(ev.bssid)) return;
    const own = ctx.ownBssids || [];
    if (own.includes(ev.bssid)) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${ev.ssid} via ${ev.bssid}`,
      expected: 'association to a learned BSSID',
      explain: explainNewMember({ observed: ev.bssid, learnedCount: known.size }),
      data: { ssid: ev.ssid, bssid: ev.bssid, mac: ev.mac },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      ssids: [...dev.ssids.entries()].map((pair) => [pair[0], [...pair[1]]]),
      clients: [...dev.clients],
      fired: dev.fired,
    };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.ssids = new Map();
    dev.clients = new Set();
    dev.fired = Boolean(state && state.fired);
    if (!state || !Array.isArray(state.ssids)) return;
    if (state.ssids.length > 256) throw new Error('array ssids exceeds cap');
    for (const pair of state.ssids) {
      if (!Array.isArray(pair) || !Array.isArray(pair[1])) continue;
      if (pair[1].length > CAP) throw new Error('array bssids exceeds cap');
      dev.ssids.set(String(pair[0]), new Set(pair[1].map(String)));
    }
    if (Array.isArray(state.clients)) {
      for (const mac of state.clients) dev.clients.add(String(mac));
    }
  },
};

module.exports = detector;
