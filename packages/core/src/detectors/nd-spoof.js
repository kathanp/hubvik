'use strict';

const { explainChanged } = require('./lib');

const CAP = 5000;

const detector = {
  id: 'nd-spoof',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['nd'],
    explains: true,
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { enabled: true, severity: 'critical' },

  createState() {
    return {};
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  learn(dev, ev, ctx) {
    return observe(ev, ctx, true);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    return observe(ev, ctx, false);
  },

  exportState() {
    return {};
  },

  importState() {},
};

/**
 * @param {any} ev
 * @param {any} ctx
 * @param {boolean} learning
 */
function observe(ev, ctx, learning) {
  if (!ev || ev.type !== 'nd' || ev.op !== 'na') return;
  const bag = shared(ctx);
  const previous = bag.bindings.get(ev.ip);
  const router = ev.router === true || (ctx.routers || []).includes(ev.ip);
  if (previous && previous !== ev.mac) {
    const key = `${ev.ip}>${ev.mac}`;
    if (!bag.fired.has(key) && (!learning || router)) {
      bag.fired.add(key);
      bag.bindings.set(ev.ip, ev.mac);
      return {
        severity: ctx.options.severity,
        confidence: router ? 0.95 : 0.85,
        ts: ev.ts,
        actual: `${ev.ip} claimed by ${ev.mac}`,
        expected: `${ev.ip} stays on ${previous}`,
        explain: explainChanged({ observed: ev.mac, previous }),
        data: { ip: ev.ip, mac: ev.mac, previous, router },
      };
    }
  }
  if (bag.bindings.size >= CAP && !bag.bindings.has(ev.ip)) return;
  bag.bindings.set(ev.ip, ev.mac);
}

/**
 * @param {any} ctx
 */
function shared(ctx) {
  let bag = ctx.scratch.get('nd-spoof');
  if (!bag) {
    bag = { bindings: new Map(), fired: new Set() };
    ctx.scratch.set('nd-spoof', bag);
  }
  return bag;
}

module.exports = detector;
