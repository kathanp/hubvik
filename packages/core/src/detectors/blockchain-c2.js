'use strict';

const { listed, seenState, exportSeen, importSeen, memorySeen, explainMatch } = require('./lib');
const RPC = require('../data/rpc.json');

const detector = {
  id: 'blockchain-c2',
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
    attack: ['T1071'],
    stage: 'c2',
    explains: true,
  },
  requires: ['T2'],
  category: 'proxy',
  hardRule: true,
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} ev */
  prepare(ev) {
    const name = ev.qname || ev.dstName;
    return typeof name === 'string' && name.length > 0;
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const name = ev.qname || ev.dstName;
    if (!name || !listed(name, RPC)) return;
    if (ctx.deviceClass && (ctx.deviceClass.id === 'wallet' || ctx.deviceClass.id === 'node'))
      return;
    if (dev.fired.has(name)) return;
    dev.fired.add(name);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: name,
      expected: 'no chain RPC or ENS lookup from this device class',
      data: { qname: name },
      explain: explainMatch({ observed: name, matched: name, source: 'rpc' }),
    };
  },

  exportState: exportSeen,

  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },

  memoryEstimate: memorySeen,
};

module.exports = detector;
