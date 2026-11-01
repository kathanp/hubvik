'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { parseArgs } = require('../cli.js');
const { suggestion, fpWilson, rowsFromResult } = require('../scorecard.js');
const { wilson } = require('../protocol.js');

test('a holdout run refuses sweep, cost, and fit-lr', () => {
  assert.throws(
    () => parseArgs(['--split', 'holdout', '--sweep', 'packet-flood.minPackets=1:2:1']),
    /holdout refuses/,
  );
  assert.throws(() => parseArgs(['--split', 'holdout', '--fit-lr']), /holdout refuses/);
});

test('suggestion follows the C6.3 gate', () => {
  assert.strictEqual(suggestion({ exercised: false, unique: 0, falsePositives: 0 }, 10), 'no-data');
  assert.strictEqual(
    suggestion({ exercised: true, unique: 2, falsePositives: 1, severity: 'medium' }, 10),
    'keep',
  );
  assert.strictEqual(
    suggestion({ exercised: true, unique: 0, falsePositives: 1, severity: 'medium' }, 10),
    'review',
  );
  assert.strictEqual(
    suggestion({ exercised: true, unique: 0, falsePositives: 10, severity: 'medium' }, 10),
    'propose-demote',
  );
  assert.strictEqual(
    suggestion({ exercised: true, unique: 0, falsePositives: 2, severity: 'high' }, 8),
    'propose-demote',
  );
  assert.strictEqual(
    suggestion({ exercised: true, unique: 0, falsePositives: 4, severity: 'info' }, 1),
    'review',
  );
});

test('Wilson matches the eval helper, and a rate above 1 has no interval', () => {
  assert.deepStrictEqual(fpWilson(1, 20), wilson(1, 20));
  assert.strictEqual(fpWilson(30, 10), null);
});

test('fewer than 20 attack instances is marked n too small and unique is kept', () => {
  const registry = new Map([['scan', { mode: 'live', hardRule: true }]]);
  const [row] = rowsFromResult(
    {
      attackInstances: 17,
      benignDeviceDays: 10,
      hits: [{ detectors: ['scan'] }],
      ablation: [
        {
          detector: 'scan',
          severity: 'medium',
          exercised: true,
          unique: 3,
          falsePositives: 1,
        },
      ],
    },
    'tune',
    registry,
  );
  assert.strictEqual(row.nTooSmall, true);
  assert.strictEqual(row.uniqueDetections, 3);
  assert.strictEqual(row.suggestion, 'keep');
  assert.strictEqual(row.fires, 2);
});
