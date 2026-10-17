'use strict';

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');
const CONSUMER = require('../data/consumer.json');

const detector = {
  id: 'proxy-relay',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: '',
    attack: ['T1090'],
    stage: 'impact',
    dedupGroup: 'proxy-relay',
  },
  requires: ['T1'],
  category: 'proxy',
  hardRule: true,
  defaults: { minDomains: 6, minCategories: 2, severity: 'critical' },

  createState() {
    return { hour: null, families: new Set(), categories: new Set(), firedHour: null };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' && ev.type !== 'dns') return;
    const family = domainFamily(ev.dstName || ev.qname || ev.dst);
    const category = family ? /** @type {Record<string, string>} */ (CONSUMER)[family] : null;
    if (!family || !category) return;
    const hour = Math.floor(ev.ts / 3600e3);
    if (dev.hour !== hour) {
      dev.hour = hour;
      dev.families = new Set();
      dev.categories = new Set();
    }
    if (dev.families.size < 64) dev.families.add(family);
    dev.categories.add(category);
    if (dev.firedHour === hour) return;
    if (
      dev.families.size < ctx.options.minDomains ||
      dev.categories.size < ctx.options.minCategories
    ) {
      return;
    }
    dev.firedHour = hour;
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: `${dev.families.size} consumer sites in ${dev.categories.size} categories`,
      expected: `< ${ctx.options.minDomains} consumer sites`,
      data: { families: [...dev.families], categories: [...dev.categories] },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { firedHour: dev.firedHour };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.firedHour = state && typeof state.firedHour === 'number' ? state.firedHour : null;
    dev.hour = null;
    dev.families = new Set();
    dev.categories = new Set();
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.families.size * 24 + 32;
  },
};

module.exports = detector;
