'use strict';

const { LruSet } = require('../engine/caps');
const { domainFamily } = require('../engine/net');
const { assertState, readStrings, fillSet } = require('./state');

const detector = {
  id: 'new-domain-family',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low: removes CDN-subdomain noise',
    attack: ['T1071'],
    stage: 'c2',
  },
  requires: ['T0'],
  category: 'destination',
  defaults: { maxNewFamiliesPerWindow: 3, severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return { families: new LruSet(caps.maxDestinations), alerted: new LruSet(caps.maxAlertKeys) };
  },

  /**
   * @param {any} dev
   * @param {string} kind
   * @param {string} value
   */
  allow(dev, kind, value) {
    const family = domainFamily(value);
    if (kind !== 'dst' || !family) return false;
    dev.families.add(family);
    return true;
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const family = domainFamily(ev.dst);
    if (family) dev.families.add(family);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const family = domainFamily(ev.dst);
    if (!family || dev.families.has(family) || dev.alerted.has(family)) return;
    dev.alerted.add(family);
    ctx.window.newFamilies = (ctx.window.newFamilies || 0) + 1;
    if (ctx.window.newFamilies > ctx.options.maxNewFamiliesPerWindow) return;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: family,
      expected: `${dev.families.size} known families`,
      data: { family, known: dev.families.size },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { families: dev.families.toArray(), alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.families = fillSet(
      readStrings(state.families, caps.maxDestinations, caps.maxString, 'families'),
      caps.maxDestinations,
    );
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return (dev.families.size + dev.alerted.size) * 48 + 32;
  },
};

module.exports = detector;
