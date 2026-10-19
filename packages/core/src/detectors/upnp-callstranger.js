'use strict';

const { isPublic, domainFamily } = require('../engine/net');
const { explainMatch } = require('./lib');

const detector = {
  id: 'upnp-callstranger',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Very low',
    consumes: ['app'],
    explains: true,
  },
  requires: ['T5'],
  category: 'exploit',
  hardRule: false,
  defaults: { enabled: true, severity: 'critical' },

  createState() {
    return { fired: false };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    if (dev.fired || !ev || ev.proto !== 'upnp' || ev.op !== 'SUBSCRIBE') return;
    const host = callbackHost(ev.target);
    if (!host || !isPublicHost(host)) return;
    dev.fired = true;
    return {
      severity: ctx.options.severity,
      confidence: 0.95,
      ts: ev.ts,
      actual: host,
      expected: 'SUBSCRIBE callbacks stay on the LAN',
      explain: explainMatch({ observed: host, matched: host, source: 'target' }),
      data: { host, target: ev.target },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { fired: dev.fired };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.fired = Boolean(state && state.fired);
  },
};

/**
 * @param {string | undefined} target
 * @returns {string | null}
 */
function callbackHost(target) {
  if (typeof target !== 'string' || target.length === 0) return null;
  const matched = /^[a-z][a-z0-9+.-]*:\/\/([^/:]+)/i.exec(target);
  const host = (matched ? matched[1] : target).replace(/^\[|\]$/g, '').toLowerCase();
  return host.length > 0 ? host : null;
}

/**
 * @param {string} host
 */
function isPublicHost(host) {
  if (host.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return isPublic(host);
  return domainFamily(host) != null;
}

module.exports = detector;
