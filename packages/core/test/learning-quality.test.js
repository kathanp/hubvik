'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

const DAY = 24 * 3600e3;

/**
 * @param {Record<string, unknown>} [extra]
 */
function flow(extra = {}) {
  return {
    type: 'flow',
    device: 'd',
    ts: 1000,
    srcIp: '10.0.0.8',
    srcPort: 40000,
    dstIp: '1.2.3.4',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 80,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 40,
    dstName: 'video.vendor.com',
    ...extra,
  };
}

test('each suspicious learning reason fires once', () => {
  const engine = createEngine({ learnMs: 10 * DAY, tiers: ['T0', 'T1', 'T2'] });
  /** @type {string[]} */
  const reasons = [];
  engine.on('warning', (warning) => {
    if (warning.code === 'SUSPICIOUS_LEARNING') reasons.push(warning.reason);
  });
  engine.feed({ device: 'd', dst: 'seed.example', bytes: 10, ts: 0 });
  for (let i = 0; i < 21; i++) {
    engine.feed({ device: 'd', dst: `host-${i}.example`, bytes: 10, ts: 2 * DAY + i });
  }
  engine.feed(flow({ ts: 2 * DAY + 100, proto: 'gre', dstPort: 0 }));
  engine.feed(flow({ ts: 2 * DAY + 200, dstPort: 23 }));
  engine.feed(flow({ ts: 2 * DAY + 300, dstPort: 5555 }));
  for (let i = 0; i < 10; i++) {
    engine.feed({
      type: 'dns',
      device: 'd',
      ts: 2 * DAY + 400,
      qname: `n${i}.example`,
      qtype: 'A',
      rcode: 'NXDOMAIN',
      resolver: '10.0.0.1',
    });
  }
  engine.feed(flow({ ts: 3 * DAY, durationMs: 60_000, dstIp: '9.9.9.9' }));
  for (let i = 0; i < 8; i++) {
    engine.feed(
      flow({
        ts: 3 * DAY + 100 + i,
        durationMs: 100,
        dstIp: `9.9.8.${i}`,
      }),
    );
  }
  assert.deepStrictEqual(
    reasons.sort(),
    ['adb', 'family-churn', 'gre', 'nxdomain-burst', 'proxy-shape', 'telnet-out'].sort(),
  );
  assert.deepStrictEqual(engine.stats().learningQuality.d.suspicious.sort(), reasons.sort());
  assert.strictEqual(engine.stats().learningQuality.d.ready, false);
});

test('lock before review warns, and a short learn window extends learning', () => {
  const dirty = createEngine({ learnMs: DAY });
  /** @type {string[]} */
  const codes = [];
  dirty.on('warning', (warning) => codes.push(warning.code));
  dirty.feed(flow({ ts: 0, proto: 'gre' }));
  dirty.lock('d');
  assert.ok(codes.includes('LOCKED_UNREVIEWED'));

  const extended = createEngine({ learnMs: 1000, minLearnWindows: 3, windowMs: 1000 });
  /** @type {string[]} */
  const extendedCodes = [];
  extended.on('warning', (warning) => extendedCodes.push(warning.code));
  extended.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 0 });
  extended.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  extended.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1000 });
  assert.deepStrictEqual(
    extendedCodes.filter((code) => code === 'LEARNING_EXTENDED'),
    ['LEARNING_EXTENDED'],
  );
  assert.strictEqual(extended.stats().learningQuality.d.ready, false);
});
