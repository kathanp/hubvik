'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const engine = createEngine({ learnMs: 86_400_000 });
engine.setDeviceTimezone('d', 'America/Chicago');
engine.feed({ device: 'd', dst: 'a.example', bytes: 10, ts: Date.UTC(2026, 9, 30, 13, 0, 0) });
process.stdout.write('ok\n');
