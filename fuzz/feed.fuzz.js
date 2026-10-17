'use strict';

const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;
const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];

/**
 * @param {() => number} rng
 * @param {number} i
 */
function event(rng, i) {
  const kind = Math.floor(rng() * 6);
  const ts = i * 1_000;
  if (kind === 0)
    return { device: 'd', dst: `h${i % 20}.example`, bytes: Math.floor(rng() * 1000), ts };
  if (kind === 1) {
    return {
      type: 'flow',
      device: 'd',
      ts,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: '1.2.3.4',
      dstPort: 443,
      proto: 'tcp',
      direction: 'out',
      bytesOut: Math.floor(rng() * 500),
      bytesIn: Math.floor(rng() * 500),
      pktsOut: 1,
      pktsIn: 1,
      durationMs: 10,
    };
  }
  if (kind === 2) {
    return {
      type: 'dns',
      device: 'd',
      ts,
      qname: `n${i % 30}.example`,
      qtype: 'A',
      rcode: 'NOERROR',
      resolver: '10.0.0.1',
      answers: [{ type: 'A', value: '1.2.3.10', ttl: 30 }],
    };
  }
  if (kind === 3) {
    return {
      type: 'dhcp',
      device: 'd',
      ts,
      mac: 'aa:bb:cc:dd:ee:ff',
      msg: 'ack',
      fingerprint: '1,3,6',
    };
  }
  if (kind === 4) return { device: '', ts };
  return JSON.parse(`{"__proto__":{"x":${i}},"device":"d","dst":"a.example","bytes":1,"ts":${ts}}`);
}

const engine = createEngine({ learnMs: 0, tiers: TIERS });
const rng = mulberry32(20261017);
let rejected = 0;
for (let i = 0; i < N; i++) {
  try {
    engine.feed(event(rng, i));
  } catch (err) {
    if (!(err instanceof Error)) throw err;
    rejected += 1;
  }
}
engine.feed({ device: 'd', dst: 'still.example', bytes: 1, ts: N * 1_000 });
if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
console.log(`feed fuzz: ${N} inputs, ${rejected} rejected`);
