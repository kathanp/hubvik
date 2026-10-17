'use strict';

const { assertState } = require('./state');

const CAP = 5000;

const detector = {
  id: 'identity-change',
  version: 1,
  meta: {
    consumes: ['dhcp'],
    rel: '0.5',
    fpRisk: 'Low; signals MAC cloning or firmware swap',
  },
  requires: ['T4'],
  category: 'link',
  defaults: { severity: 'high' },

  createState() {
    return { macs: new Map(), allowed: new Set() };
  },

  /**
   * @param {any} dev
   * @param {string} kind
   * @param {string} value
   * @returns {boolean}
   */
  allow(dev, kind, value) {
    if (kind !== 'fingerprint') return false;
    if (!(dev.allowed instanceof Set)) dev.allowed = new Set();
    if (dev.allowed.size < CAP) dev.allowed.add(value);
    return true;
  },

  /**
   * Keep the first fingerprint. A later one is a learning warning, not a replacement.
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   * @returns {{ reason: string, message: string } | void}
   */
  learn(dev, ev, ctx) {
    const row = dhcpRow(ev);
    if (!row) return;
    const bag = shared(ctx, dev);
    const known = bag.macs.get(row.mac);
    if (known === row.fingerprint) return;
    if (known != null) {
      return {
        reason: 'identity-change',
        message: `${row.mac} DHCP fingerprint changed during learning`,
      };
    }
    if (bag.macs.size >= CAP) return;
    bag.macs.set(row.mac, row.fingerprint);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const row = dhcpRow(ev);
    if (!row) return;
    const bag = shared(ctx, dev);
    const known = bag.macs.get(row.mac);
    if (known == null || known === row.fingerprint) return;
    if (dev.allowed instanceof Set && dev.allowed.has(row.fingerprint)) return;
    const key = `${row.mac}\0${row.fingerprint}`;
    if (bag.fired.has(key)) return;
    if (bag.fired.size < CAP) bag.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${row.mac} fingerprint changed`,
      expected: known,
      data: { mac: row.mac, fingerprint: row.fingerprint, previous: known },
    };
  },

  /**
   * @param {any} dev
   */
  exportState(dev) {
    const macs = dev.macs instanceof Map ? [...dev.macs.entries()] : [];
    /** @type {{ macs: [string, string][], allowed?: string[] }} */
    const out = { macs };
    if (dev.allowed instanceof Set && dev.allowed.size > 0) {
      out.allowed = [...dev.allowed].sort();
    }
    return out;
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.macs = new Map();
    dev.allowed = new Set();
    if (state.macs != null) {
      if (!Array.isArray(state.macs)) throw new Error('macs must be an array');
      if (state.macs.length > CAP) throw new Error('array macs exceeds cap');
      for (const pair of state.macs) {
        if (!Array.isArray(pair) || pair.length !== 2) throw new Error('macs must be pairs');
        if (typeof pair[0] !== 'string' || typeof pair[1] !== 'string') {
          throw new Error('macs must be strings');
        }
        dev.macs.set(pair[0], pair[1]);
      }
    }
    if (state.allowed != null) {
      if (!Array.isArray(state.allowed)) throw new Error('allowed must be an array');
      if (state.allowed.length > CAP) throw new Error('array allowed exceeds cap');
      for (const value of state.allowed) {
        if (typeof value !== 'string') throw new Error('allowed must be strings');
        dev.allowed.add(value);
      }
    }
  },

  /**
   * @param {any} dev
   */
  memoryEstimate(dev) {
    const allowed = dev.allowed instanceof Set ? dev.allowed.size : 0;
    return (dev.macs instanceof Map ? dev.macs.size : 0) * 48 + allowed * 48;
  },
};

/**
 * @param {any} ev
 * @returns {{ mac: string, fingerprint: string } | null}
 */
function dhcpRow(ev) {
  if (ev.type !== 'dhcp' || typeof ev.fingerprint !== 'string' || ev.fingerprint.length === 0) {
    return null;
  }
  if (typeof ev.mac !== 'string' || ev.mac.length === 0) return null;
  return { mac: ev.mac, fingerprint: ev.fingerprint };
}

/**
 * One fingerprint table for the LAN.
 * @param {any} ctx
 * @param {any} dev
 */
function shared(ctx, dev) {
  let bag = ctx.scratch.get('identity-change');
  if (!bag) {
    bag = {
      macs: dev.macs instanceof Map ? dev.macs : new Map(),
      fired: new Set(),
    };
    ctx.scratch.set('identity-change', bag);
  } else if (dev.macs instanceof Map && dev.macs !== bag.macs) {
    for (const [mac, fp] of dev.macs) {
      if (bag.macs.has(mac) || bag.macs.size >= CAP) continue;
      bag.macs.set(mac, fp);
    }
  }
  dev.macs = bag.macs;
  return bag;
}

module.exports = detector;
