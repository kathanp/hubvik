'use strict';

const { domainFamily } = require('../engine/net');

/**
 * @param {any} rule
 * @param {any} ev
 * @param {number} hour
 * @returns {boolean}
 */
function matches(rule, ev, hour) {
  const match = rule.match;
  if (match.direction && ev.direction !== match.direction) return false;
  if (match.proto && String(ev.proto) !== String(match.proto)) return false;
  if (match.port != null) {
    const ports = Array.isArray(match.port) ? match.port : [match.port];
    if (!ports.includes(ev.dstPort)) return false;
  }
  if (match.hour != null) {
    const hours = Array.isArray(match.hour) ? match.hour : [match.hour];
    if (!hours.includes(hour)) return false;
  }
  if (match.dst) {
    const names = [ev.dst, ev.dstName, ev.qname].filter((value) => typeof value === 'string');
    const patterns = Array.isArray(match.dst) ? match.dst : [match.dst];
    const ok = patterns.some((/** @type {string} */ pattern) =>
      names.some((name) => {
        if (pattern.startsWith('*.'))
          return name === pattern.slice(2) || name.endsWith(pattern.slice(1));
        return name === pattern || domainFamily(name) === pattern;
      }),
    );
    if (!ok) return false;
  }
  return true;
}

const detector = {
  id: 'policy-violation',
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
    fpRisk: '',
  },
  requires: ['T0'],
  category: 'policy',
  hardRule: true,
  defaults: { severity: 'high' },

  createState() {
    return { fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const rules = ctx.policy;
    if (!Array.isArray(rules) || rules.length === 0) return;
    const hour = ctx.hour(ev.ts);
    /** @type {any[]} */
    const drafts = [];
    for (const rule of rules) {
      if (!matches(rule, ev, hour)) continue;
      const key = `${rule.id}|${ev.dst || ev.dstIp || ''}|${ev.dstPort || ''}`;
      if (dev.fired.has(key)) continue;
      if (dev.fired.size >= 5000) break;
      dev.fired.add(key);
      drafts.push({
        severity: rule.severity || ctx.options.severity,
        confidence: 0.95,
        ts: ev.ts,
        actual: rule.id,
        expected: 'traffic allowed by policy',
        data: { rule: rule.id, dst: ev.dst || ev.dstIp || null, port: ev.dstPort ?? null },
      });
    }
    return drafts.length ? drafts : undefined;
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: [...dev.fired].slice(0, 5000) };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    dev.fired = new Set();
    const fired = state && state.fired;
    if (fired == null) return;
    if (!Array.isArray(fired) || fired.length > 5000) throw new Error('array fired exceeds cap');
    for (const key of fired) {
      if (typeof key !== 'string') throw new Error('fired must be strings');
      dev.fired.add(key);
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.fired.size * 48;
  },
};

module.exports = detector;
