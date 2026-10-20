'use strict';

const { explainChanged } = require('./lib');

const detector = {
  id: 'dhcpv6-rogue',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Very low',
    consumes: ['dhcp'],
    explains: true,
  },
  requires: ['T4'],
  category: 'link',
  hardRule: false,
  defaults: { enabled: true, severity: 'critical' },

  createState() {
    return { server: null, fired: new Set() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    if (!v6(ev) || dev.server) return;
    dev.server = ev.serverIp;
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (!v6(ev)) return;
    const allowed = ctx.dhcpServers || [];
    if (allowed.length > 0) {
      if (allowed.includes(ev.serverIp) || dev.fired.has(ev.serverIp)) return;
      dev.fired.add(ev.serverIp);
      return alert(ctx, ev, allowed.join(','));
    }
    if (!dev.server) {
      dev.server = ev.serverIp;
      return;
    }
    if (dev.server === ev.serverIp || dev.fired.has(ev.serverIp)) return;
    dev.fired.add(ev.serverIp);
    return alert(ctx, ev, dev.server);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { server: dev.server };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.server = state && typeof state.server === 'string' ? state.server : null;
    dev.fired = new Set();
  },
};

/**
 * @param {any} ev
 */
function v6(ev) {
  return (
    ev &&
    ev.type === 'dhcp' &&
    ev.v6 === true &&
    (ev.msg === 'offer' || ev.msg === 'ack') &&
    ev.serverIp
  );
}

/**
 * @param {any} ctx
 * @param {any} ev
 * @param {string} expected
 */
function alert(ctx, ev, expected) {
  return {
    severity: ctx.options.severity,
    confidence: 0.95,
    ts: ev.ts,
    actual: ev.serverIp,
    expected: `DHCPv6 from ${expected}`,
    explain: explainChanged({ observed: ev.serverIp, previous: expected }),
    data: { serverIp: ev.serverIp },
  };
}

module.exports = detector;
