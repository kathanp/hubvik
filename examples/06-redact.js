'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const engine = createEngine({
  learnMs: 0,
  redact: { key: 'example-key' },
});
engine.on('anomaly', (row) => process.stdout.write(`${row.device}\n`));
engine.feed({ device: 'camera-1', dst: 'a.example', bytes: 10, ts: 1_000 });
engine.feed({ device: 'camera-1', dst: 'b.example', bytes: 10, ts: 2_000 });
