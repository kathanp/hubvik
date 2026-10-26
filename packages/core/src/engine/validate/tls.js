'use strict';

const { requireFields, num, normalizeName, coerceIp, copyUid } = require('./common');

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function tlsEvent(raw, ts, warnings) {
  requireFields(raw, ['dstIp', 'dstPort'], 'tls');
  /** @type {Record<string, any>} */
  const event = {
    type: 'tls',
    tier: 'T3',
    device: raw.device,
    ts,
    dstIp: coerceIp(raw.dstIp),
    dstPort: num(raw.dstPort, 'dstPort', { integer: true, max: 65535 }),
  };
  if (raw.sni != null) {
    const sni = normalizeName(raw.sni, 255);
    if (sni) event.sni = sni;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped tls.sni' });
  }
  if (raw.ja4 != null) {
    if (typeof raw.ja4 === 'string' && raw.ja4.length <= 255) event.ja4 = raw.ja4;
    else warnings.push({ code: 'FIELD_DROPPED', message: 'dropped tls.ja4' });
  }
  if (typeof raw.version === 'string' && raw.version.length > 0 && raw.version.length <= 32) {
    event.version = raw.version;
  } else if (raw.version != null) {
    warnings.push({ code: 'FIELD_DROPPED', message: 'dropped tls.version' });
  }
  if (Array.isArray(raw.alpn)) {
    event.alpn = raw.alpn
      .filter(
        (/** @type {unknown} */ item) =>
          typeof item === 'string' && item.length > 0 && item.length <= 32,
      )
      .slice(0, 8);
  }
  if (raw.cert && typeof raw.cert === 'object' && !Array.isArray(raw.cert)) {
    /** @type {Record<string, any>} */
    const cert = {};
    if (typeof raw.cert.issuer === 'string') cert.issuer = raw.cert.issuer.slice(0, 255);
    if (typeof raw.cert.subject === 'string') cert.subject = raw.cert.subject.slice(0, 255);
    if (typeof raw.cert.sha256 === 'string') cert.sha256 = raw.cert.sha256.slice(0, 64);
    if (typeof raw.cert.selfSigned === 'boolean') cert.selfSigned = raw.cert.selfSigned;
    if (typeof raw.cert.notBefore === 'number' && Number.isFinite(raw.cert.notBefore)) {
      cert.notBefore = raw.cert.notBefore;
    }
    if (typeof raw.cert.notAfter === 'number' && Number.isFinite(raw.cert.notAfter)) {
      cert.notAfter = raw.cert.notAfter;
    }
    event.cert = cert;
  }
  copyUid(raw, event, warnings);
  return event;
}

module.exports = { tlsEvent };
