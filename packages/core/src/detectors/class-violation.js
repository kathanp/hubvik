'use strict';

const { domainFamily, isBogon } = require('../engine/net');
const { assertState } = require('./state');

const detector = {
  id: 'class-violation',
  version: 1,
  meta: {
    rel: '0.3',
    fpRisk: 'Low. No class is set until `setDeviceClass`.',
  },
  requires: ['T0'],
  category: 'posture',
  hardRule: true,
  defaults: { severity: 'high' },

  createState() {
    return {
      families: new Set(),
      hour: null,
      upload: 0,
      firedFamilies: false,
      firedUpload: false,
      firedLan: false,
    };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const cls = ctx.deviceClass;
    if (!cls) return;
    const family = domainFamily(ev.dst || ev.dstName || ev.qname);
    if (family && dev.families.size < 64) dev.families.add(family);
    const hour = Math.floor(ev.ts / 3600e3);
    if (dev.hour !== hour) {
      dev.hour = hour;
      dev.upload = 0;
    }
    if (ev.type === 'flow') dev.upload += ev.bytesOut || 0;
    /** @type {any[]} */
    const drafts = [];
    if (!dev.firedFamilies && dev.families.size > cls.maxFamilies) {
      dev.firedFamilies = true;
      drafts.push(
        draft(ctx, ev, `${dev.families.size} families`, `<= ${cls.maxFamilies} for ${cls.id}`, {
          families: dev.families.size,
          classId: cls.id,
        }),
      );
    }
    if (!dev.firedUpload && dev.upload > cls.maxUploadBytesPerHour) {
      dev.firedUpload = true;
      drafts.push(
        draft(
          ctx,
          ev,
          `${dev.upload} bytes uploaded in an hour`,
          `<= ${cls.maxUploadBytesPerHour} for ${cls.id}`,
          {
            upload: dev.upload,
            classId: cls.id,
          },
        ),
      );
    }
    if (
      !dev.firedLan &&
      !cls.allowsInboundLan &&
      ev.type === 'flow' &&
      ev.direction === 'lan' &&
      isBogon(ev.srcIp)
    ) {
      dev.firedLan = true;
      drafts.push(
        draft(ctx, ev, `inbound LAN from ${ev.srcIp}`, `${cls.id} does not take LAN sessions`, {
          srcIp: ev.srcIp,
          classId: cls.id,
        }),
      );
    }
    return drafts;
  },

  /** @param {any} dev */
  exportState(dev) {
    return {
      families: [...dev.families],
      firedFamilies: dev.firedFamilies,
      firedUpload: dev.firedUpload,
      firedLan: dev.firedLan,
    };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.families = new Set(Array.isArray(state.families) ? state.families.slice(0, 64) : []);
    dev.firedFamilies = Boolean(state.firedFamilies);
    dev.firedUpload = Boolean(state.firedUpload);
    dev.firedLan = Boolean(state.firedLan);
    dev.hour = null;
    dev.upload = 0;
  },

  /** @param {any} dev */
  memoryEstimate(dev) {
    return dev.families.size * 32 + 32;
  },
};

/**
 * @param {any} ctx
 * @param {any} ev
 * @param {string} actual
 * @param {string} expected
 * @param {object} data
 */
function draft(ctx, ev, actual, expected, data) {
  return {
    severity: ctx.options.severity,
    confidence: 0.85,
    ts: ev.ts,
    actual,
    expected,
    data,
  };
}

module.exports = detector;
