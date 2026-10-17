'use strict';

const { LruSet } = require('../engine/caps');
const { exactHit } = require('../engine/indicators');
const { assertState, readStrings, fillSet } = require('./state');

const CONSENT = new Set(['smart-tv', 'tv-box']);

const detector = {
  id: 'proxy-sdk-traffic',
  version: 1,
  meta: {
    consumes: [
      'summary',
      'flow',
      'dns',
      'tls',
      'http',
      'arp',
      'dhcp',
      'ra',
      'discovery',
      'mapping',
      'app',
    ],
    rel: '0.5',
    fpRisk: "Depends on the host's list",
  },
  requires: ['T2'],
  category: 'proxy',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    const hit = proxyHit(ctx.indicatorIndex, ev);
    if (!hit) return;
    const key = hit.value.toLowerCase();
    if (dev.alerted.has(key)) return;
    dev.alerted.add(key);
    const classId = ctx.deviceClass && ctx.deviceClass.id;
    const consentPossible = CONSENT.has(classId);
    return {
      severity: consentPossible ? 'medium' : ctx.options.severity,
      confidence: hit.confidence,
      ts: ev.ts,
      actual: hit.value,
      expected: 'no contact with a residential-proxy SDK',
      data: { value: hit.value, source: hit.source, consentPossible },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { alerted: dev.alerted.toArray() };
  },

  /**
   * @param {any} dev
   * @param {any} state
   * @param {any} caps
   */
  importState(dev, state, caps) {
    assertState(state, detector.id);
    dev.alerted = fillSet(
      readStrings(state.alerted, caps.maxAlertKeys, caps.maxString, 'alerted'),
      caps.maxAlertKeys,
    );
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.alerted.size * 48;
  },
};

/**
 * Domain-style match for a host-supplied proxy-sdk indicator.
 * @param {any} index
 * @param {any} ev
 */
function proxyHit(index, ev) {
  if (!index) return null;
  const names = [ev.qname, ev.dstName, ev.sni].filter(
    (value) => typeof value === 'string' && value.length > 0,
  );
  const ts = ev.ts || 0;
  for (const name of names) {
    const labels = name.toLowerCase().split('.').filter(Boolean);
    for (let i = 0; i < labels.length - 1; i++) {
      const hit = exactHit(index, 'proxy-sdk', labels.slice(i).join('.'), ts);
      if (hit) return hit;
    }
  }
  return null;
}

module.exports = detector;
