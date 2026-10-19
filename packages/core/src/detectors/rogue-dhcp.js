'use strict';

const { assertState } = require('./state');
const { explainChanged } = require('./lib');

const detector = {
  id: 'rogue-dhcp',
  version: 1,
  meta: {
    consumes: ['dhcp'],
    rel: '0.3',
    fpRisk: 'Very low',
    explains: true,
  },
  requires: ['T4'],
  category: 'link',
  hardRule: true,
  defaults: { severity: 'critical' },

  createState() {
    return { server: null, fired: new Set() };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (ev.type !== 'dhcp' || (ev.msg !== 'offer' && ev.msg !== 'ack') || !ev.serverIp) return;
    const allowed = ctx.dhcpServers || [];
    if (allowed.length > 0) {
      if (allowed.includes(ev.serverIp) || dev.fired.has(ev.serverIp)) return;
      dev.fired.add(ev.serverIp);
      return alert(ctx, ev, ev.serverIp, allowed.join(','));
    }
    if (!dev.server) {
      dev.server = ev.serverIp;
      return;
    }
    if (dev.server === ev.serverIp || dev.fired.has(ev.serverIp)) return;
    dev.fired.add(ev.serverIp);
    return alert(ctx, ev, ev.serverIp, dev.server);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { server: dev.server };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.server = state && typeof state.server === 'string' ? state.server : null;
    dev.fired = new Set();
  },

  memoryEstimate() {
    return 24;
  },
};

/**
 * @param {any} ctx
 * @param {any} ev
 * @param {string} server
 * @param {string} expected
 */
function alert(ctx, ev, server, expected) {
  return {
    severity: ctx.options.severity,
    confidence: 0.95,
    ts: ev.ts,
    actual: server,
    expected: `DHCP from ${expected}`,
    data: { serverIp: server },
    explain: explainChanged({ observed: server, previous: expected }),
  };
}

module.exports = detector;
