'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createHmac } = require('node:crypto');
const { createSender } = require('../src/index.js');

test('retries, then sends the HMAC header', async () => {
  /** @type {{ url: string, body: string, headers: Record<string, string> }[]} */
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, body: init.body, headers: init.headers });
    if (calls.length < 3) return { ok: false, status: 503 };
    return { ok: true, status: 200 };
  };
  const sender = createSender({
    url: 'https://example.test/hook',
    fetch,
    sign: 'lab-key',
    backoffMs: 1,
    sleep: async () => {},
  });
  const response = await sender.send({ id: '1', detector: 'cert-change' });
  assert.strictEqual(response.status, 200);
  assert.strictEqual(calls.length, 3);
  const body = JSON.stringify({ id: '1', detector: 'cert-change' });
  const mac = createHmac('sha256', 'lab-key').update(body).digest('hex');
  assert.strictEqual(calls[2].headers['x-hubvik-signature'], mac);
});

test('rejects a sender without a url and a thrown fetch', async () => {
  assert.throws(() => createSender({ url: 'https://example.test/hook' }), /url and fetch/);
  const sender = createSender({
    url: 'https://example.test/hook',
    fetch: async () => {
      throw new Error('down');
    },
    maxAttempts: 1,
    sleep: async () => {},
  });
  await assert.rejects(() => sender.send({ id: '1' }), /webhook failed/);
});

test('throws after the last failed attempt', async () => {
  const sender = createSender({
    url: 'https://example.test/hook',
    fetch: async () => ({ ok: false, status: 500 }),
    maxAttempts: 2,
    sleep: async () => {},
  });
  await assert.rejects(() => sender.send({ id: '1' }), /webhook failed/);
});
