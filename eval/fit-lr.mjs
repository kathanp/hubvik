import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { loadSweepDataset } = require('./sweep.js');
const { operatingPoint } = require('./protocol.js');

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const OUT = path.join(ROOT, 'eval', 'results', 'lr-proposal.json');
const seed = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'packages', 'core', 'src', 'data', 'lr.json'), 'utf8'),
);

const loaded = loadSweepDataset({}, { cacheDir: path.join(ROOT, 'eval', '.cache') });
const measured = operatingPoint(loaded.rows, { tiers: loaded.tiers });
const attacks = measured.attackInstances;
const days = measured.benignDeviceDays;
const qualified = attacks >= 20 && days >= 50;

const proposal = {
  version: 1,
  seed: true,
  dataset: 'synthetic',
  attackInstances: attacks,
  benignDeviceDays: days,
  note: qualified
    ? 'Labeled corpus meets the fit gate. The seed table is still the default until a person accepts a proposal.'
    : `Synthetic corpus has ${attacks} attack instances and ${days} benign device-days. The fit needs at least 20 and 50, so this file keeps the seed table. IoT-23 captures are not on disk.`,
  detectors: seed.detectors,
};

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, `${JSON.stringify(proposal, null, 2)}\n`);
console.log(`wrote ${OUT}`);
