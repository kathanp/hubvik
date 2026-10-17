'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'upnp-port-open',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Low',
  },
  requires: ['T1'],
  category: 'exposure',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const key = mappingKey(ev);
    if (key) dev.seen.add(key);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const key = mappingKey(ev);
    if (!key || dev.seen.has(key) || dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.9,
      ts: ev.ts,
      actual: key,
      expected: 'no new WAN port mapping',
      data: { proto: ev.proto, port: ev.port },
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
function mappingKey(ev) {
  if (ev.type !== 'mapping') return null;
  return `${ev.proto}:${ev.externalPort || ev.port}`;
}

module.exports = detector;
