'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const engine = createEngine({ learnMs: 0 });
engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: 1_000 });
engine.setPeerGroup('d', 'cams');
const summary = engine.exportSummary({ key: 'example-key', gatewayId: 'gw-a' });
process.stdout.write(`${summary.gatewayId}\n`);
