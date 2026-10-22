'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { loadSweepDataset } = require('./sweep');
const { operatingPoint } = require('./protocol');

/**
 * Format one measured rate. The number comes from operatingPoint.
 * @param {number | null} rate
 * @param {string} wilson
 * @returns {string}
 */
function rate(rateValue, wilson) {
  if (rateValue == null) return 'no rate';
  return `${rateValue} per benign device-day (${wilson})`;
}

/**
 * Replay the synthetic fixture four ways and write eval/results/fp-reduction.md.
 * IoT-23 captures are not scored here.
 * @param {{ cacheDir?: string, outPath?: string }} [opts]
 * @returns {string}
 */
function writeFpReduction(opts = {}) {
  const loaded = loadSweepDataset(
    {},
    { cacheDir: opts.cacheDir || path.join(__dirname, '.cache') },
  );
  const base = { tiers: loaded.tiers, alerts: true };
  const additive = operatingPoint(loaded.rows, base);
  const lr = operatingPoint(loaded.rows, { ...base, scoring: 'lr' });
  const additiveNoted = operatingPoint(loaded.rows, { ...base, annotate: true });
  const lrNoted = operatingPoint(loaded.rows, { ...base, scoring: 'lr', annotate: true });
  const lines = [
    '# Likelihood-ratio versus additive scoring',
    '',
    'Measured on the synthetic fixture. The likelihood-ratio option stays off by default.',
    '',
    `Dataset: synthetic. Attack instances: ${additive.attackInstances}. Benign device-days: ${additive.benignDeviceDays}.`,
    '',
    '| scoring | annotations | anomaly false positives | anomaly FP/device-day | alert false positives | alert FP/device-day | detection |',
    '| --- | --- | --- | --- | --- | --- | --- |',
    row('additive', 'off', additive),
    row('lr', 'off', lr),
    row('additive', 'on', additiveNoted),
    row('lr', 'on', lrNoted),
    '',
    'IoT-23: needs dataset run by a person.',
    '',
    'The seed table is `packages/core/src/data/lr.json`. `eval/fit-lr.mjs` writes `eval/results/lr-proposal.json` and does not edit the seed.',
    '',
  ];
  const text = `${lines.join('\n')}\n`;
  const file = opts.outPath || path.join(__dirname, 'results', 'fp-reduction.md');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return text;
}

/**
 * @param {string} scoring
 * @param {string} annotations
 * @param {any} point
 * @returns {string}
 */
function row(scoring, annotations, point) {
  return `| ${scoring} | ${annotations} | ${point.falsePositives} | ${rate(point.fpPerDeviceDay, point.fpPerDeviceDayWilson)} | ${point.alertFalsePositives} | ${rate(point.alertFpPerDeviceDay, point.alertFpPerDeviceDayWilson)} | ${point.detection} |`;
}

if (require.main === module) {
  writeFpReduction();
}

module.exports = { writeFpReduction };
