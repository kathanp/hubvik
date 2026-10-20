'use strict';

/**
 * Render one response hint as nftables rule text. This function never executes a rule.
 * @param {{ action?: string, target?: string, fingerprint?: string, expiryMs?: number }} hint
 * @param {{ table?: string, chain?: string, family?: string }} [opts]
 */
function render(hint, opts = {}) {
  const family = opts.family || 'inet';
  const table = opts.table || 'iotwarden';
  const chain = opts.chain || 'forward';
  const action = hint && hint.action ? hint.action : 'review';
  const target = sanitize(hint && hint.target ? hint.target : '');
  const fingerprint = sanitize(hint && hint.fingerprint ? hint.fingerprint : '');
  const expiry = hint && hint.expiryMs ? String(hint.expiryMs) : '0';
  const comment = `iotwarden ${fingerprint} exp ${expiry}`;
  if (action === 'review' || action === 'relearn' || !target) {
    return `add rule ${family} ${table} ${chain} comment "${comment}"`;
  }
  const match = looksLikeIp(target) ? `ip saddr ${target}` : `comment "${comment} ${target}"`;
  const verb = action === 'rate-limit' ? 'limit rate 10/second' : 'drop';
  return `add rule ${family} ${table} ${chain} ${match} ${verb} comment "${comment}"`;
}

/**
 * @param {string} value
 */
function sanitize(value) {
  if (/[;{}\\\n\r\s"]/.test(value)) throw new TypeError('hint target is invalid');
  return value;
}

/**
 * @param {string} value
 */
function looksLikeIp(value) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':');
}

module.exports = { render };
