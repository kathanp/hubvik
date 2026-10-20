'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const engine = createEngine({ learnMs: 0 });
engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
const saved = engine.exportBaseline({ createdAt: 1 });
const next = createEngine({ learnMs: 0 });
next.importBaseline(saved);
process.stdout.write(`${next.exportBaseline({ createdAt: 1 }).version}\n`);
