'use strict';

const { HubvikError } = require('../errors');

const { domainFamily } = require('../engine/net');
const { createBloom, add, has } = require('../engine/stats/bloom');
const { scratchBag } = require('./lib');
const { assertState } = require('./state');

const DAY = 24 * 60 * 60 * 1000;
const ROTATE = 15 * DAY;

/**
 * @param {any} ev
 * @returns {string | null}
 */
function familyOf(ev) {
  const name = ev.qname || ev.dstName || ev.dst;
  return domainFamily(name);
}

/**
 * @param {any} ctx
 * @param {number} ts
 */
function filters(ctx, ts) {
  const bag = scratchBag(ctx, 'lan-bloom', () => ({
    current: createBloom(),
    previous: createBloom(),
    start: ts,
  }));
  while (ts >= bag.start + ROTATE) {
    bag.previous = bag.current;
    bag.current = createBloom();
    bag.start += ROTATE;
  }
  return bag;
}

const detector = {
  id: 'lan-first-seen-domain',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'High alone; that is why it is low and capped',
    consumes: ['dns', 'flow', 'summary'],
    attack: ['T1071'],
  },
  requires: ['T2'],
  category: 'dns',
  hardRule: false,
  defaults: { severity: 'low' },

  createState() {
    return { day: null, count: 0 };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    const family = familyOf(ev);
    if (!family) return;
    add(filters(ctx, ev.ts).current, family);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const family = familyOf(ev);
    if (!family) return;
    const bag = filters(ctx, ev.ts);
    const seen = has(bag.current, family) || has(bag.previous, family);
    add(bag.current, family);
    if (seen) return;
    const day = Math.floor(ev.ts / DAY);
    if (dev.day !== day) {
      dev.day = day;
      dev.count = 0;
    }
    if (dev.count >= 20) return;
    dev.count += 1;
    return {
      severity: ctx.options.severity,
      confidence: 0.4,
      ts: ev.ts,
      actual: family,
      expected: 'a family seen on this network in the last 30 days',
      data: { family },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { day: dev.day, count: dev.count };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.day = null;
    dev.count = 0;
    if (!state) return;
    if (state.count != null) {
      if (!Number.isInteger(state.count) || state.count < 0 || state.count > 20) {
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array count exceeds cap');
      }
      dev.count = state.count;
    }
    if (state.day != null) dev.day = state.day;
  },

  memoryEstimate() {
    return 16;
  },
};

module.exports = detector;
