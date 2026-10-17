'use strict';

const { LruSet } = require('../engine/caps');
const { isBogon, isIpName } = require('../engine/net');
const { assertState, readStrings, fillSet } = require('./state');

const detector = {
  id: 'dns-rebinding',
  version: 1,
  meta: {
    rel: '0.2',
    fpRisk: 'Low',
    attack: ['T1557'],
    dedupGroup: 'private-answer',
  },
  requires: ['T2'],
  category: 'dns',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return { alerted: new LruSet(caps.maxAlertKeys) };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !Array.isArray(ev.answers) || isIpName(ev.qname)) return;
    for (const answer of ev.answers) {
      if (!answer || typeof answer.value !== 'string' || !isBogon(answer.value)) continue;
      const key = `${ev.qname}|${answer.value}`;
      if (dev.alerted.has(key)) return;
      dev.alerted.add(key);
      return {
        severity: ctx.options.severity,
        confidence: 0.9,
        ts: ev.ts,
        actual: `${ev.qname} -> ${answer.value}`,
        expected: 'public names resolve to public addresses',
        data: { qname: ev.qname, answer: answer.value },
      };
    }
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
