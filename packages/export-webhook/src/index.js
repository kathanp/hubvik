'use strict';

const { createHmac } = require('node:crypto');

/**
 * POST anomalies to a URL. Pass `fetch` so tests never touch the network.
 * `sign` is the HMAC-SHA256 key. The header is `x-iotwarden-signature`.
 * Failed responses are retried with exponential backoff.
 * @param {{ url: string, fetch: typeof fetch, sign?: string | Buffer, maxAttempts?: number, backoffMs?: number, sleep?: (ms: number) => Promise<void> }} opts
 */
function createSender(opts) {
  if (!opts || typeof opts.url !== 'string' || typeof opts.fetch !== 'function') {
    throw new TypeError('webhook needs a url and fetch');
  }
  const maxAttempts = opts.maxAttempts == null ? 3 : opts.maxAttempts;
  const backoffMs = opts.backoffMs == null ? 200 : opts.backoffMs;
  const sleep = opts.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  return {
    /**
     * @param {object} anomaly
     */
    async send(anomaly) {
      const body = JSON.stringify(anomaly);
      /** @type {Record<string, string>} */
      const headers = { 'content-type': 'application/json' };
      if (opts.sign != null) {
        headers['x-iotwarden-signature'] = createHmac('sha256', opts.sign)
          .update(body)
          .digest('hex');
      }
      let last = null;
      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        try {
          const response = await opts.fetch(opts.url, { method: 'POST', headers, body });
          if (response && response.ok) return response;
          last = response;
        } catch (err) {
          last = err;
        }
        if (attempt + 1 < maxAttempts) await sleep(backoffMs * 2 ** attempt);
      }
      const error = new Error('webhook failed');
      error.cause = last;
      throw error;
    },
  };
}

module.exports = { createSender };
