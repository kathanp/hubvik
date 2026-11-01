import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { writeScorecard } = require('./scorecard-cli.js');

const rows = writeScorecard();
const counts = { keep: 0, review: 0, 'propose-demote': 0, 'no-data': 0 };
for (const row of rows) counts[row.suggestion] = (counts[row.suggestion] || 0) + 1;
console.log(`scorecard: ${rows.length} rows ${JSON.stringify(counts)}`);
