'use strict';

const { listed, seenState, exportSeen, importSeen, memorySeen, explainMatch } = require('./lib');
const POOLS = require('../data/pools.json');

const detector = {
  id: 'cryptomining',
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
    fpRisk: '',
    attack: ['T1496'],
    stage: 'impact',
    explains: true,
  },
  requires: ['T1'],
  category: 'monetization',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} ev */
  prepare(ev) {
    return !!signal(ev);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const hit = signal(ev);
    if (!hit || dev.fired.has(hit)) return;
    dev.fired.add(hit);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: hit,
      expected: 'no mining pool or stratum session',
      data: { hit },
      explain: explainMatch({ observed: hit, matched: hit, source: 'pool' }),
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
 * @param {any} ev
 * @returns {string | null}
 */
function signal(ev) {
  if (
    ev.type === 'app' &&
    ev.proto === 'stratum' &&
    /mining\.(subscribe|authorize)/.test(String(ev.op))
  ) {
    return ev.op;
  }
  const name = ev.qname || ev.dstName;
  if (name && listed(name, POOLS)) return name;
  return null;
}

module.exports = detector;
