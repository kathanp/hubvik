#!/usr/bin/env node
'use strict';

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const require = createRequire(import.meta.url);
const { ALL } = require(join(ROOT, 'packages/core/src/detectors/index.js'));

/** Engine-integrity rows in SPEC B11. */
const INTEGRITY = ['input-gap', 'clock-jump', 'state-cap', 'alert-storm', 'tier-silent'];

const scorecardPath = join(ROOT, 'eval/results/scorecard.json');
const scorecard = JSON.parse(readFileSync(scorecardPath, 'utf8'));
const keep = new Set(
  scorecard
    .filter((row) => row.split === 'tune' && row.suggestion === 'keep' && row.mode === 'live')
    .map((row) => row.id),
);
const ids = new Set(INTEGRITY);
for (const det of ALL) {
  if (det.hardRule === true) ids.add(det.id);
}
for (const id of keep) ids.add(id);
const body = {
  generatedFrom: 'eval/results/scorecard.json',
  rule: 'D-119',
  ids: [...ids].sort(),
};
const out = join(ROOT, 'packages/core/src/data/profiles/core.json');
mkdirSync(join(ROOT, 'packages/core/src/data/profiles'), { recursive: true });
writeFileSync(out, `${JSON.stringify(body, null, 2)}\n`);
console.log(`core profile: ${body.ids.length} ids, keep ${keep.size}`);
