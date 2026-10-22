'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createEngine } = require('../../src/index.js');

/**
 * @param {Record<string, unknown>} extra
 */
function flow(extra) {
  return {
    type: 'flow',
    device: 'cam',
    ts: 1_000,
    srcIp: '10.0.0.8',
    srcPort: 40_000,
    dstIp: '8.8.8.8',
    dstPort: 443,
    proto: 'tcp',
    direction: 'out',
    bytesOut: 100,
    bytesIn: 100,
    pktsOut: 1,
    pktsIn: 1,
    durationMs: 10,
    dstName: 'update.vendor.com',
    splt: { len: [64, 64, 64, 64], iat: [1, 1, 1, 1] },
    ...extra,
  };
}

test('flow-shape-change keeps its learned histogram across export and import', () => {
  const eng = createEngine({ shadow: true, flowShape: true, learnMs: 5_000, tiers: ['T1'] });
  eng.feed(flow({}));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const next = createEngine({ shadow: true, flowShape: true, learnMs: 0, tiers: ['T1'] });
  next.importBaseline(saved);
  const round = next.exportBaseline({ createdAt: 1 });
  assert.deepEqual(
    round.devices.cam.detectors['flow-shape-change'].state.families,
    saved.devices.cam.detectors['flow-shape-change'].state.families,
  );
  const families = [];
  for (let i = 0; i < 17; i += 1) families.push([`f${i}.com`, new Array(16).fill(0)]);
  assert.throws(
    () =>
      next.importBaseline({
        ...saved,
        devices: {
          cam: {
            ...saved.devices.cam,
            detectors: {
              ...saved.devices.cam.detectors,
              'flow-shape-change': { v: 1, state: { families, fired: false } },
            },
          },
        },
      }),
    /exceeds cap/,
  );
});
