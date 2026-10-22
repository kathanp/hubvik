'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const DAY = 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;

/**
 * @param {any} ev
 * @returns {string | null}
 */
function familyOf(ev) {
  return domainFamily(ev.qname || ev.dstName || ev.dst);
}

const detector = {
  id: 'dormant-reactivation',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk:
      'Medium: seasonal devices that update firmware on wake. A G3 firmware-update annotation removes it from scoring',
    consumes: ['summary', 'flow', 'dns'],
    attack: ['T1195'],
  },
  requires: ['T0'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { days: new Set(), last: null, wake: null, families: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const day = Math.floor(ev.ts / DAY);
    if (dev.days.size < 64) dev.days.add(day);
    dev.last = ev.ts;
    const family = familyOf(ev);
    if (family && dev.families.size < 256) dev.families.add(family);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (dev.fired || dev.days.size < 3 || dev.last == null) {
      dev.last = ev.ts;
      return;
    }
    if (dev.wake == null && ev.ts - dev.last >= 7 * DAY) dev.wake = ev.ts;
    dev.last = ev.ts;
    if (dev.wake == null || ev.ts - dev.wake > HOUR) return;
    const family = familyOf(ev);
    if (!family || dev.families.has(family)) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `woke and contacted ${family}`,
      expected: 'a family already in the baseline',
      data: { family, wake: dev.wake },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      days: [...dev.days],
      last: dev.last,
      wake: dev.wake,
      families: [...dev.families],
      fired: dev.fired,
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.days = new Set();
    dev.families = new Set();
    dev.last = null;
    dev.wake = null;
    dev.fired = Boolean(state && state.fired);
    if (!state) return;
    if (Array.isArray(state.days)) {
      if (state.days.length > 64)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array days exceeds cap');
      for (const day of state.days) dev.days.add(day);
    }
    if (Array.isArray(state.families)) {
      if (state.families.length > 256)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array families exceeds cap');
      for (const name of state.families) dev.families.add(String(name));
    }
    if (typeof state.last === 'number') dev.last = state.last;
    if (typeof state.wake === 'number') dev.wake = state.wake;
  },

  memoryEstimate() {
    return 64;
  },
};

module.exports = detector;
