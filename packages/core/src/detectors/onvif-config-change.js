'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const OPS = new Set([
  'SetUser',
  'SetNetworkInterfaces',
  'SetSystemFactoryDefault',
  'UpgradeSystemFirmware',
]);

const detector = {
  id: 'onvif-config-change',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
    attack: ['T1562'],
  },
  requires: ['T5'],
  category: 'app',
  hardRule: true,
  defaults: { severity: 'critical' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'app' || ev.proto !== 'onvif' || !OPS.has(ev.op)) return;
    const key = `${ev.peerIp}|${ev.op}`;
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.95,
      ts: ev.ts,
      actual: ev.op,
      expected: 'no user, network, reset, or firmware change',
      data: { op: ev.op, peerIp: ev.peerIp },
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
