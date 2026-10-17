'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { mulberry32 } = require('../../../test/fixtures/prng');

/**
 * @param {() => number} rng
 * @param {number} i
 */
function corrupt(rng, i) {
  const kind = Math.floor(rng() * 5);
  if (kind === 0) return null;
  if (kind === 1) return [];
  if (kind === 2) return { version: 99, devices: {}, scratch: {} };
  if (kind === 3) return { version: 2, devices: null, scratch: { [`nope-${i}`]: { i } } };
  return JSON.parse(`{"__proto__":{"polluted":${i}},"version":2,"devices":{}}`);
}

test('arp spoof fires after restore when the attacker claims the gateway', () => {
  const opts = { learnMs: 0, tiers: ['T4'], gatewayIp: '10.0.0.1' };
  const engine = createEngine(opts);
  engine.feed({
    type: 'arp',
    device: 'gw',
    ts: 1_000,
    ip: '10.0.0.1',
    mac: 'aa:aa:aa:aa:aa:aa',
    op: 'reply',
  });
  const saved = engine.checkpoint({ createdAt: 1, sign: 'secret' });
  const attack = {
    type: 'arp',
    device: 'x',
    ts: 2_000,
    ip: '10.0.0.1',
    mac: 'bb:bb:bb:bb:bb:bb',
    op: 'reply',
  };
  const fresh = createEngine(opts);
  /** @type {any[]} */
  const quiet = [];
  fresh.on('anomaly', (item) => {
    if (item.detector === 'arp-spoof') quiet.push(item);
  });
  fresh.feed(attack);
  assert.strictEqual(quiet.length, 0);

  const restored = createEngine(opts);
  /** @type {any[]} */
  const alerts = [];
  restored.on('anomaly', (item) => {
    if (item.detector === 'arp-spoof') alerts.push(item);
  });
  restored.restore(saved, { verify: 'secret' });
  restored.feed(attack);
  assert.strictEqual(alerts.length, 1);
  assert.strictEqual(alerts[0].data.previous, 'aa:aa:aa:aa:aa:aa');
  assert.throws(() => restored.restore({ ...saved, watermark: 9 }, { verify: 'secret' }));
});

test('a thousand corrupt checkpoints are rejected and leave state unchanged', () => {
  const engine = createEngine({ learnMs: 0 });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  const before = JSON.stringify(engine.exportBaseline({ createdAt: 1 }));
  const rng = mulberry32(1);
  for (let i = 0; i < 1000; i++) {
    const junk = corrupt(rng, i);
    assert.throws(() => engine.restore(junk));
  }
  assert.strictEqual(JSON.stringify(engine.exportBaseline({ createdAt: 1 })), before);
});

test('a checkpoint with a broken fleet-wave table is rejected', () => {
  const engine = createEngine({ learnMs: 0, tiers: ['T0'] });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  const saved = engine.checkpoint({ createdAt: 1 });
  const before = engine.stats().devices;
  const broken = JSON.parse(JSON.stringify(saved));
  broken.scratch['fleet-wave'] = { map: true };
  assert.throws(() => engine.restore(broken), /fleet-wave/);
  assert.strictEqual(engine.stats().devices, before);
  engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 60_000 });
});
