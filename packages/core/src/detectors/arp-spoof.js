'use strict';

const { HubvikError } = require('../errors');

const { assertState } = require('./state');
const { explainChanged, explainThreshold, scratchBag } = require('./lib');

const detector = {
  id: 'arp-spoof',
  version: 1,
  meta: {
    consumes: ['arp', 'dhcp'],
    rel: '0.3',
    fpRisk: 'Low (DHCP reassignments handled via lease events)',
    attack: ['T1557.002'],
    explains: true,
  },
  requires: ['T4'],
  category: 'link',
  hardRule: true,
  defaults: { maxIpsPerMac: 8, severity: 'critical' },

  createState() {
    return { bindings: new Map(), macIps: new Map(), fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const bag = shared(ctx);
    if (ev.type === 'dhcp' && (ev.msg === 'ack' || ev.msg === 'offer') && ev.requestedIp) {
      bag.bindings.set(ev.requestedIp, ev.mac);
      return;
    }
    if (ev.type !== 'arp' || (ev.op !== 'reply' && ev.op !== 'gratuitous')) return;
    const previous = bag.bindings.get(ev.ip);
    const gateway = ctx.gatewayIp && ev.ip === ctx.gatewayIp;
    if (previous && previous !== ev.mac && (!ctx.learning || gateway)) {
      const key = `${ev.ip}>${ev.mac}`;
      if (!bag.fired.has(key)) {
        bag.fired.add(key);
        bag.bindings.set(ev.ip, ev.mac);
        return {
          severity: ctx.options.severity,
          confidence: gateway ? 0.95 : 0.85,
          ts: ev.ts,
          actual: `${ev.ip} claimed by ${ev.mac}`,
          expected: `${ev.ip} stays on ${previous}`,
          data: { ip: ev.ip, mac: ev.mac, previous, gateway: Boolean(gateway) },
          explain: explainChanged({ observed: ev.mac, previous }),
        };
      }
    }
    bag.bindings.set(ev.ip, ev.mac);
    let ips = bag.macIps.get(ev.mac);
    if (!ips) {
      ips = new Set();
      bag.macIps.set(ev.mac, ips);
    }
    if (ips.size < 64) ips.add(ev.ip);
    if (ctx.learning || ips.size <= ctx.options.maxIpsPerMac || bag.fired.has(ev.mac)) return;
    bag.fired.add(ev.mac);
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${ev.mac} claims ${ips.size} addresses`,
      expected: `<= ${ctx.options.maxIpsPerMac} addresses per MAC`,
      data: { mac: ev.mac, ips: ips.size },
      explain: explainThreshold({
        test: 'gt',
        observed: ips.size,
        threshold: ctx.options.maxIpsPerMac,
        formula: `maxIpsPerMac=${ctx.options.maxIpsPerMac}`,
      }),
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { bindings: [...dev.bindings.entries()] };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.bindings = new Map();
    dev.macIps = new Map();
    dev.fired = new Set();
    if (!Array.isArray(state.bindings)) return;
    if (state.bindings.length > 5000)
      throw new HubvikError('ARRAY_BINDINGS_EXCEEDS_CAP', 'array bindings exceeds cap');
    for (const pair of state.bindings) {
      if (!Array.isArray(pair) || pair.length !== 2)
        throw new HubvikError('BINDINGS_MUST_BE_PAIRS', 'bindings must be pairs');
      dev.bindings.set(String(pair[0]), String(pair[1]));
    }
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.bindings.size * 32 + 16;
  },
};

/**
 * One binding table for the LAN. ARP is not a per-device fact.
 * @param {any} ctx
 */
function shared(ctx) {
  return scratchBag(ctx, 'arp-spoof', () => ({
    bindings: new Map(),
    macIps: new Map(),
    fired: new Set(),
  }));
}

module.exports = detector;
