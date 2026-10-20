'use strict';

const { assertState } = require('./state');

const HOUR = 3_600_000;

const detector = {
  id: 'mac-randomization-churn',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Medium', consumes: ['dhcp'] },
  requires: ['T4'],
  category: 'identity',
  defaults: { enabled: true, severity: 'info' },

  createState() {
    return { prints: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dhcp' || typeof ev.fingerprint !== 'string' || typeof ev.mac !== 'string')
      return;
    let row = dev.prints.get(ev.fingerprint);
    if (!row) {
      if (dev.prints.size >= 256) {
        const oldest = dev.prints.keys().next().value;
        if (oldest != null) dev.prints.delete(oldest);
      }
      row = [];
      dev.prints.set(ev.fingerprint, row);
    }
    const fresh = row.filter((/** @type {{ ts: number }} */ item) => ev.ts - item.ts <= HOUR);
    if (
      !fresh.some((/** @type {{ mac: string }} */ item) => item.mac === ev.mac) &&
      fresh.length < 8
    ) {
      fresh.push({ mac: ev.mac, ts: ev.ts });
    }
    dev.prints.set(ev.fingerprint, fresh);
    if (fresh.length < 5 || dev.fired.has(ev.fingerprint)) return;
    dev.fired.add(ev.fingerprint);
    return {
      severity: ctx.options.severity,
      confidence: 0.4,
      ts: ev.ts,
      actual: `${fresh.length} MACs for one DHCP fingerprint`,
      expected: 'a stable MAC for this fingerprint',
      data: { fingerprint: ev.fingerprint, macs: fresh.length },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      prints: [...dev.prints.entries()].slice(0, 256).map(([fingerprint, macs]) => ({
        fingerprint,
        macs,
      })),
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.prints = new Map();
    dev.fired = new Set();
    const rows = Array.isArray(state.prints) ? state.prints.slice(0, 256) : [];
    for (const row of rows) {
      if (!row || typeof row.fingerprint !== 'string' || !Array.isArray(row.macs)) continue;
      dev.prints.set(row.fingerprint, row.macs.slice(0, 8));
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.prints.size * 64 + 16;
  },
};

module.exports = detector;
