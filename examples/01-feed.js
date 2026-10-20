'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const engine = createEngine({ learnMs: 0 });
engine.on('anomaly', (row) => process.stdout.write(`${row.detector}\n`));
engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
engine.feed({ device: 'd', dst: 'b.example', bytes: 10, ts: 2_000 });
