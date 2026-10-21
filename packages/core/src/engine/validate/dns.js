'use strict';

const { HubvikError } = require('../../errors');

const { requireFields, normalizeName } = require('./common');

/**
 * @param {any} raw
 * @param {number} ts
 * @param {{ code: string, message: string }[]} warnings
 */
function dnsEvent(raw, ts, warnings) {
  requireFields(raw, ['qname', 'qtype', 'rcode', 'resolver'], 'dns');
  const qname = normalizeName(raw.qname, 255);
  if (!qname) throw new HubvikError('DNS_QNAME_IS_INVALID', 'dns qname is invalid');
  /** @type {Record<string, any>} */
  const event = {
    type: 'dns',
    tier: 'T2',
    device: raw.device,
    ts,
    qname,
    qtype: String(raw.qtype),
    rcode: String(raw.rcode),
    resolver: String(raw.resolver),
  };
  if (raw.answers != null) {
    if (!Array.isArray(raw.answers)) {
      warnings.push({ code: 'FIELD_DROPPED', message: 'dropped dns.answers' });
    } else {
      const answers = [];
      for (const answer of raw.answers) {
        if (!answer || typeof answer !== 'object' || typeof answer.type !== 'string') continue;
        answers.push({
          type: answer.type,
          value: answer.value == null ? '' : String(answer.value).slice(0, 255),
          ttl: typeof answer.ttl === 'number' && Number.isFinite(answer.ttl) ? answer.ttl : 0,
        });
      }
      event.answers = answers;
    }
  }
  if (typeof raw.from === 'string' && raw.from.length > 0 && raw.from.length <= 64)
    event.from = raw.from;
  if (Number.isInteger(raw.port) && raw.port >= 0 && raw.port <= 65535) event.port = raw.port;
  return event;
}

module.exports = { dnsEvent };
