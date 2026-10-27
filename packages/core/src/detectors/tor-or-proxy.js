'use strict';

const { exactHit } = require('../engine/indicators');
const { seenState, exportSeen, importSeen, memorySeen, explainMatch } = require('./lib');

const detector = {
  id: 'tor-or-proxy',
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
    rel: '0.3',
    fpRisk: 'Very low for IoT',
    attack: ['T1090.003'],
    stage: 'c2',
    explains: true,
  },
  requires: ['T1'],
  category: 'destination',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} ev @param {any} ctx */
  prepare(ev, ctx) {
    const index = ctx && ctx.indicatorIndex;
    if (!index || (index.exact.size === 0 && index.v4.size === 0)) return false;
    return !!(ev.dstIp || ev.dst || ev.dstName || ev.qname);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const hit = torHit(ctx.indicatorIndex, ev);
    if (!hit) return;
    const key = String(hit.value);
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: hit.confidence ?? 0.9,
      ts: ev.ts,
      actual: key,
      expected: 'no Tor relay or anonymizer',
      data: { value: key, source: hit.source },
      explain: explainMatch({ observed: key, matched: key, source: hit.source || 'tor' }),
    };
  },

  exportState: exportSeen,

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },

  memoryEstimate: memorySeen,
};

/**
 * @param {any} index
 * @param {any} ev
 */
function torHit(index, ev) {
  if (!index) return null;
  const ts = ev.ts || 0;
  for (const ip of [ev.dstIp, ev.dst]) {
    if (typeof ip !== 'string') continue;
    const hit = exactHit(index, 'tor', ip, ts);
    if (hit) return hit;
  }
  for (const name of [ev.dstName, ev.qname, ev.dst]) {
    if (typeof name !== 'string') continue;
    const labels = name.toLowerCase().split('.').filter(Boolean);
    for (let i = 0; i < labels.length - 1; i++) {
      const hit = exactHit(index, 'tor', labels.slice(i).join('.'), ts);
      if (hit) return hit;
    }
    const exact = exactHit(index, 'tor', name.toLowerCase(), ts);
    if (exact) return exact;
  }
  return null;
}

module.exports = detector;
