'use strict';

const { ipv4, inBlock } = require('../engine/net');
const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'zone-violation',
  version: 1,
  meta: {
    consumes: ['flow'],
    rel: '0.3',
    fpRisk: '',
  },
  requires: ['T1'],
  category: 'policy',
  defaults: { severity: 'high' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'flow' || ev.direction !== 'lan' || !ctx.zones || ctx.zones.length === 0)
      return;
    const src = zoneOf(ev.srcIp, ctx.zones);
    const dst = zoneOf(ev.dstIp, ctx.zones);
    if (!src || !dst || src === dst) return;
    const key = `${src}>${dst}`;
    if (dev.fired.has(key)) return;
    dev.fired.add(key);
    return {
      severity: ctx.options.severity,
      confidence: 0.85,
      ts: ev.ts,
      actual: `${src} to ${dst}`,
      expected: 'traffic stays inside one zone',
      data: { srcZone: src, dstZone: dst },
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
 * @param {string} ip
 * @param {{ id: string, base: number, bits: number }[]} zones
 */
function zoneOf(ip, zones) {
  const value = ipv4(ip);
  if (value == null) return null;
  for (const zone of zones) {
    if (inBlock(value, zone.base, zone.bits)) return zone.id;
  }
  return null;
}

module.exports = detector;
