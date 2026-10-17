'use strict';

const { listed, seenState, exportSeen, importSeen, memorySeen } = require('./lib');
const TUNNELS = require('../data/tunnels.json');

const detector = {
  id: 'tunnel-service',
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
    attack: ['T1572'],
    stage: 'c2',
  },
  requires: ['T2'],
  category: 'tunnel',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const hit = nameOf(ev);
    if (hit) dev.seen.add(hit);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const hit = nameOf(ev);
    if (!hit || dev.seen.has(hit) || dev.fired.has(hit)) return;
    dev.fired.add(hit);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: hit,
      expected: 'no new tunnel or remote-access service',
      data: { name: hit },
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
 */
function nameOf(ev) {
  const name = ev.qname || ev.dstName;
  if (!name || !listed(name, TUNNELS)) return null;
  return name;
}

module.exports = detector;
