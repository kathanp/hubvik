'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'answer-drift',
  version: 1,
  meta: {
    consumes: ['dns'],
    rel: '0.4',
    fpRisk: 'Medium (CDN changes); could indicate DNS hijack or spoofing',
  },
  requires: ['T2'],
  category: 'dns',
  defaults: { severity: 'high' },

  createState() {
    return { answers: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    remember(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dns' || !ev.qname || !Array.isArray(ev.answers)) return;
    const previous = dev.answers.get(ev.qname);
    const next = keys(ev, ctx);
    if (!previous) {
      remember(dev, ev, ctx);
      return;
    }
    const novel = next.find((key) => !previous.includes(key));
    if (!novel || dev.fired.has(ev.qname)) return;
    dev.fired.add(ev.qname);
    return {
      severity: ctx.options.severity,
      confidence: 0.75,
      ts: ev.ts,
      actual: `${ev.qname} -> ${novel}`,
      expected: `${ev.qname} -> ${previous[0]}`,
      data: { qname: ev.qname, answer: novel, previous },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { answers: [...dev.answers.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    if (!Array.isArray(state.answers)) throw new Error('answer-drift answers must be an array');
    if (state.answers.length > 5000) throw new Error('array answer-drift.answers exceeds cap');
    dev.answers = new Map();
    dev.fired = new Set();
    for (const pair of state.answers) {
      if (Array.isArray(pair) && Array.isArray(pair[1]))
        dev.answers.set(String(pair[0]), pair[1].slice(0, 8));
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.answers.size * 48 + 16;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function remember(dev, ev, ctx) {
  if (ev.type !== 'dns' || !ev.qname) return;
  const list = keys(ev, ctx);
  if (!list.length) return;
  const previous = dev.answers.get(ev.qname) || [];
  const merged = previous.slice();
  for (const key of list) {
    if (!merged.includes(key) && merged.length < 8) merged.push(key);
  }
  dev.answers.set(ev.qname, merged);
}

/**
 * @param {any} ev
 * @param {any} ctx
 */
function keys(ev, ctx) {
  /** @type {string[]} */
  const list = [];
  for (const answer of ev.answers || []) {
    if (!answer || answer.type !== 'A' || !answer.value) continue;
    const found = typeof ctx.lookup === 'function' ? ctx.lookup(answer.value) : null;
    list.push(found && found.asn ? found.asn : answer.value);
  }
  return list.slice(0, 8);
}

module.exports = detector;
