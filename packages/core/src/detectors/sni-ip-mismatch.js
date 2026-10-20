'use strict';

const { domainFamily } = require('../engine/net');
const { assertState } = require('./state');

const HOUR = 3_600_000;

const detector = {
  id: 'sni-ip-mismatch',
  version: 1,
  meta: { rel: '0.9', mode: 'shadow', fpRisk: 'Medium', consumes: ['dns', 'tls'] },
  requires: ['T2', 'T3'],
  category: 'tls',
  defaults: { enabled: true, severity: 'high' },

  createState() {
    return { names: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    note(dev, ev);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    note(dev, ev);
    if (ev.type !== 'tls' || typeof ev.sni !== 'string') return;
    const family = domainFamily(ev.sni);
    const row = family ? dev.names.get(family) : null;
    if (!row || ev.ts - row.ts > HOUR) return;
    if (row.ips.includes(ev.dstIp) || dev.fired.has(`${family}|${ev.dstIp}`)) return;
    if (dev.fired.size >= 64) return;
    dev.fired.add(`${family}|${ev.dstIp}`);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${ev.sni} via ${ev.dstIp}`,
      expected: `an address returned for ${family}`,
      dedupKey: `${family}|${ev.dstIp}`,
      data: { family, dstIp: ev.dstIp, answers: row.ips.slice() },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      names: [...dev.names.entries()].map(([family, row]) => ({
        family,
        ips: row.ips,
        ts: row.ts,
      })),
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.names = new Map();
    dev.fired = new Set();
    const rows = Array.isArray(state.names) ? state.names.slice(0, 64) : [];
    for (const row of rows) {
      if (!row || typeof row.family !== 'string') continue;
      dev.names.set(row.family, {
        ips: Array.isArray(row.ips) ? row.ips.slice(0, 8).map(String) : [],
        ts: row.ts || 0,
      });
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.names.size * 80 + 16;
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 */
function note(dev, ev) {
  if (ev.type !== 'dns') return;
  const family = domainFamily(ev.qname);
  if (!family) return;
  let row = dev.names.get(family);
  if (!row) {
    if (dev.names.size >= 64) {
      const oldest = dev.names.keys().next().value;
      if (oldest != null) dev.names.delete(oldest);
    }
    row = { ips: [], ts: ev.ts };
    dev.names.set(family, row);
  }
  row.ts = ev.ts;
  for (const answer of ev.answers || []) {
    if (row.ips.length >= 8) break;
    if (answer && answer.type === 'A' && !row.ips.includes(answer.value))
      row.ips.push(answer.value);
  }
}

module.exports = detector;
