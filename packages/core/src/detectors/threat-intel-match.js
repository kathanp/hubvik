'use strict';

const { LruSet } = require('../engine/caps');
const { matchEvent } = require('../engine/indicators');
const { assertState, readStrings, fillSet } = require('./state');
const { explainMatch } = require('./lib');

const detector = {
  id: 'threat-intel-match',
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
    rel: '0.2',
    fpRisk: 'Depends on feed quality',
    attack: ['T1071'],
    stage: 'c2',
    dedupGroup: 'indicator',
    explains: true,
  },
  requires: ['T0'],
  category: 'destination',
  hardRule: true,
  defaults: { severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const index = ctx.indicatorIndex;
    const hit = matchEvent(index, ev);
    if (!hit) return;
    const key = `${hit.type}|${hit.value}`;
    if (dev.alerted.has(key)) return;
    dev.alerted.add(key);
    return {
      severity: ctx.options.severity,
      confidence: hit.confidence,
      ts: ev.ts,
      actual: hit.value,
      expected: 'destination not on a supplied indicator list',
      data: { type: hit.type, value: hit.value, source: hit.source },
      explain: explainMatch({
        observed: hit.value,
        matched: hit.value,
        source: hit.source || 'indicator',
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { alerted: dev.alerted.toArray() };
  },

  /** @param {any} dev @param {any} state @param {any} caps */
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

module.exports = detector;
