'use strict';

const { explainThreshold } = require('./lib');

const SKIP = new Set(['hub', 'nas', 'smart-tv']);

const detector = {
  id: 'graph-role-change',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Low',
    consumes: ['flow'],
    explains: true,
  },
  requires: ['T1'],
  category: 'lateral',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minDegree: 5, learnedMax: 1 },

  createState() {
    return { learnedMax: 0, fired: false };
  },

  /**
   * @param {any} dev
   * @param {any} _summary
   * @param {any} ctx
   */
  onWindowClose(dev, _summary, ctx) {
    if (skip(ctx) || dev.fired) return;
    const degree = ctx.lanInDegree || 0;
    if (ctx.learning) {
      if (degree > dev.learnedMax) dev.learnedMax = degree;
      return;
    }
    if (dev.learnedMax > ctx.options.learnedMax) return;
    if (degree < ctx.options.minDegree) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ctx.ts,
      actual: `${degree} LAN peers`,
      expected: `learned max in-degree ${dev.learnedMax}`,
      explain: explainThreshold({
        test: 'gte',
        observed: degree,
        threshold: ctx.options.minDegree,
        formula: 'LAN in-degree, learned max <= 1',
        learned: { max: dev.learnedMax },
      }),
      data: { degree, learnedMax: dev.learnedMax },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { learnedMax: dev.learnedMax, fired: dev.fired };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.learnedMax = state && typeof state.learnedMax === 'number' ? state.learnedMax : 0;
    dev.fired = Boolean(state && state.fired);
  },
};

/**
 * @param {any} ctx
 */
function skip(ctx) {
  const id = ctx.deviceClass && ctx.deviceClass.id;
  return typeof id === 'string' && SKIP.has(id);
}

module.exports = detector;
