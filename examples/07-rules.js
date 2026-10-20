'use strict';

const { createEngine } = require('../packages/core/src/index.js');

const engine = createEngine({ learnMs: 0 });
engine.loadRules([
  {
    id: 'one-host',
    mode: 'shadow',
    on: 'summary',
    window: '1m',
    severity: 'low',
    category: 'policy',
  },
]);
process.stdout.write('ok\n');
