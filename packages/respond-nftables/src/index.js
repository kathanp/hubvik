'use strict';

/**
 * Render one response hint as nftables rule text. This function never executes a rule.
 * @param {{ action?: string, target?: string, fingerprint?: string, expiryMs?: number }} hint
 * @param {{ table?: string, chain?: string, family?: string }} [opts]
 */
function render(hint, opts = {}) {
  const family = ident(opts.family, 'inet');
  const table = ident(opts.table, 'hubvik');
  const chain = ident(opts.chain, 'forward');
  const action = hint && hint.action ? hint.action : 'review';
  const target = sanitize(hint && hint.target ? hint.target : '');
  const fingerprint = sanitize(hint && hint.fingerprint ? hint.fingerprint : '');
  const expiry = hint && hint.expiryMs ? String(Math.trunc(Number(hint.expiryMs)) || 0) : '0';
  const comment = `hubvik ${fingerprint} exp ${expiry}`;
  if (action === 'review' || action === 'relearn' || !target) {
    return `add rule ${family} ${table} ${chain} comment "${comment}"`;
  }
  const match = addressMatch(target) || `comment "${comment} ${target}"`;
  const verb = action === 'rate-limit' ? 'limit rate 10/second' : 'drop';
  return `add rule ${family} ${table} ${chain} ${match} ${verb} comment "${comment}"`;
}

/**
 * @param {string} value
 */
function sanitize(value) {
  if (/[;{}\\#\n\r\s"'`$]/.test(value)) throw new TypeError('hint target is invalid');
  return value;
}

/**
 * @param {unknown} value
 * @param {string} fallback
 * @returns {string}
 */
function ident(value, fallback) {
  const text = value == null || value === '' ? fallback : String(value);
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,31}$/.test(text)) {
    throw new TypeError('hint target is invalid');
  }
  return text;
}

/**
 * IPv4 uses `ip saddr`. IPv6 uses `ip6 saddr`. Anything else is not an address match.
 * @param {string} value
 * @returns {string | null}
 */
function addressMatch(value) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
    const ok = value.split('.').every((part) => Number(part) <= 255);
    if (ok) return `ip saddr ${value}`;
  }
  if (value.includes(':') && value.length <= 45 && /^[0-9a-f:]+$/i.test(value)) {
    return `ip6 saddr ${value}`;
  }
  return null;
}

module.exports = { render };
