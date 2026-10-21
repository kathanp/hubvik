'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { readSamples, readStreamState } = require('../../src/detectors/samples.js');

test('sample import rejects a bad state and keeps a valid summary', () => {
  assert.throws(() => readStreamState(null, 8, 'volume-spike'), /state is invalid/);
  assert.throws(() => readStreamState([], 8, 'volume-spike'), /state is invalid/);
  assert.throws(
    () => readStreamState({ samples: 'no' }, 8, 'volume-spike'),
    /samples must be an array/,
  );
  assert.throws(() => readStreamState({ samples: [1, 2, 3] }, 2, 'volume-spike'), /exceeds cap/);
  assert.throws(
    () => readStreamState({ samples: [Number.NaN] }, 8, 'volume-spike'),
    /non-negative/,
  );
  assert.strictEqual(readStreamState({ samples: [1, 3] }, 8, 'volume-spike').count, 2);
  assert.throws(
    () => readStreamState({ count: -1, mean: 0, m2: 0, max: 0 }, 8, 'volume-spike'),
    /count is invalid/,
  );
  assert.throws(
    () => readStreamState({ count: 1, mean: Number.NaN, m2: 0, max: 1 }, 8, 'volume-spike'),
    /mean is invalid/,
  );
  assert.throws(
    () => readStreamState({ count: 1, mean: 1, m2: 0, max: -1 }, 8, 'volume-spike'),
    /max is invalid/,
  );
  assert.deepStrictEqual(readStreamState({ count: 2, mean: 1, m2: 0, max: 4 }, 8, 'volume-spike'), {
    count: 2,
    mean: 1,
    m2: 0,
    max: 4,
  });
  assert.throws(() => readSamples(null, { maxWindows: 4 }, 'fan-out'), /state is invalid/);
  assert.strictEqual(readSamples({ samples: [1, 2] }, { maxWindows: 4 }, 'fan-out').length, 2);
});
