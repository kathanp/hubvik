'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'fast-flux',
  version: 1,
  meta: {
    consumes: ['dns'],
    rel: '0.4',
    fpRisk: 'Medium',
  },
  requires: ['T2'],
  category: 'dns',
  defaults: { minAnswers: 8, maxTtl: 60, severity: 'high' },

  createState() {
    return { win: null, byName: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !ev.qname || !Array.isArray(ev.answers)) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.byName = new Map();
      dev.fired = new Set();
    }
    let row = dev.byName.get(ev.qname);
    if (!row) {
      row = { ips: new Set(), lowTtl: false };
      dev.byName.set(ev.qname, row);
    }
    for (const answer of ev.answers) {
      if (!answer || answer.type !== 'A') continue;
      if (row.ips.size < 64) row.ips.add(answer.value);
      if (answer.ttl <= ctx.options.maxTtl) row.lowTtl = true;
    }
    if (dev.fired.has(ev.qname) || !row.lowTtl || row.ips.size < ctx.options.minAnswers) return;
    dev.fired.add(ev.qname);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${ev.qname} has ${row.ips.size} short-lived answers`,
      expected: `< ${ctx.options.minAnswers} answers, or a normal TTL`,
      data: { qname: ev.qname, answers: row.ips.size },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.byName = new Map();
    dev.fired = new Set();
  },

  memoryEstimate() {
    return 32;
  },
};

module.exports = detector;
