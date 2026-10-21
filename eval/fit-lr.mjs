import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = path.join(ROOT, 'eval', 'results', 'lr-proposal.json');
const seed = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'packages', 'core', 'src', 'data', 'lr.json'), 'utf8'),
);

const proposal = {
  version: 1,
  seed: true,
  note: 'IoT-23 captures are not on disk, so this file keeps the seed table. A person re-runs eval/fit-lr.mjs after a labeled corpus exists.',
  detectors: seed.detectors,
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(proposal, null, 2)}\n`);
console.log(`wrote ${OUT}`);
