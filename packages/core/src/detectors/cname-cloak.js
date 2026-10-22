'use strict';

const { HubvikError } = require('../errors');

const { exactHit } = require('../engine/indicators');
const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const DAY = 24 * 60 * 60 * 1000;
const TYPES = ['ad', 'tracker', 'proxy-sdk'];

const detector = {
  id: 'cname-cloak',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: "Depends on the host's lists",
    consumes: ['dns'],
    attack: ['T1090'],
  },
  requires: ['T2'],
  category: 'dns',
  hardRule: false,
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return { families: new Set(), fired: new Map(), cap: caps.maxDestinations };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const family = domainFamily(ev.qname);
    if (family && dev.families.size < dev.cap) dev.families.add(family);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !Array.isArray(ev.answers) || !ctx.indicatorIndex) return;
    const start = domainFamily(ev.qname);
    if (!start || !dev.families.has(start)) return;
    let end = null;
    for (const answer of ev.answers) {
      if (answer && answer.type === 'CNAME' && answer.value)
        end = domainFamily(answer.value) || answer.value;
    }
    if (!end || end === start) return;
    let hit = null;
    for (const type of TYPES) {
      hit = exactHit(ctx.indicatorIndex, type, end, ev.ts);
      if (hit) break;
    }
    if (!hit) return;
    const key = `${end}`;
    const at = dev.fired.get(key);
    if (typeof at === 'number' && ev.ts - at < DAY) return;
    dev.fired.set(key, ev.ts);
    return {
      severity: ctx.options.severity,
      confidence: hit.confidence || 0.7,
      ts: ev.ts,
      actual: `${start} CNAME to ${end}`,
      expected: 'a CNAME chain that stays off tracker lists',
      data: { start, end, type: hit.type },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { families: [...dev.families], fired: [...dev.fired.entries()], cap: dev.cap };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.families = new Set();
    dev.fired = new Map();
    dev.cap = state && Number.isInteger(state.cap) ? state.cap : dev.cap;
    if (!state) return;
    if (Array.isArray(state.families)) {
      if (state.families.length > dev.cap)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array families exceeds cap');
      for (const name of state.families) dev.families.add(String(name));
    }
    if (Array.isArray(state.fired)) {
      if (state.fired.length > dev.cap)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array fired exceeds cap');
      for (const pair of state.fired) {
        if (Array.isArray(pair)) dev.fired.set(String(pair[0]), Number(pair[1]) || 0);
      }
    }
  },

  memoryEstimate(/** @type {any} */ dev) {
    return 32 + dev.families.size * 16;
  },
};

module.exports = detector;
