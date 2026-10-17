'use strict';

const { assertState } = require('./state');

const detector = {
  id: 'credential-stuffing-out',
  version: 1,
  meta: {
    consumes: ['flow', 'tls'],
    rel: '0.4',
    fpRisk: '',
    dedupGroup: 'proxy-relay',
  },
  requires: ['T1'],
  category: 'monetization',
  defaults: { minSites: 15, severity: 'high' },

  createState() {
    return { win: null, sites: new Set(), fired: false };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const site = siteOf(ev);
    if (!site) return;
    const start = ctx.window && ctx.window.start;
    if (dev.win !== start) {
      dev.win = start;
      dev.sites = new Set();
      dev.fired = false;
    }
    if (dev.sites.size < 64) dev.sites.add(site);
    if (dev.fired || dev.sites.size < ctx.options.minSites) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.8,
      ts: ev.ts,
      actual: `${dev.sites.size} short logins`,
      expected: `< ${ctx.options.minSites} unrelated login targets per window`,
      data: { sites: dev.sites.size },
    };
  },

  exportState() {
    return {};
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.win = null;
    dev.sites = new Set();
    dev.fired = false;
  },

  memoryEstimate() {
    return 32;
  },
};

/**
 * @param {any} ev
 */
function siteOf(ev) {
  const short = (ev.durationMs || 0) <= 3000;
  if (!short) return null;
  if (ev.type === 'tls' && ev.dstPort === 443) return ev.sni || ev.dstIp;
  if (ev.type === 'flow' && ev.direction === 'out' && ev.dstPort === 443)
    return ev.dstName || ev.dstIp;
  return null;
}

module.exports = detector;
