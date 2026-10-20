'use strict';

const { readFileSync, readdirSync } = require('node:fs');
const { join } = require('node:path');
const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;
const rng = mulberry32(20261022);
const SEVERITY = ['info', 'low', 'medium', 'high', 'critical'];
const WINDOW = ['1m', '5m', '1h', '24h'];
const examples = readdirSync(join(__dirname, '../examples/rules'))
  .filter((name) => name.endsWith('.json'))
  .map((name) => JSON.parse(readFileSync(join(__dirname, '../examples/rules', name), 'utf8')));

/**
 * @param {any} rule
 * @param {() => number} next
 */
function safe(rule, next) {
  const pick = Math.floor(next() * 6);
  if (pick === 0) rule.severity = SEVERITY[Math.floor(next() * SEVERITY.length)];
  else if (pick === 1 && typeof rule.window === 'string') {
    rule.window = WINDOW[Math.floor(next() * WINDOW.length)];
  } else if (pick === 2 && rule.when) {
    const key = Object.keys(rule.when)[0];
    const pred = key && rule.when[key];
    if (pred && typeof pred.gt === 'number') pred.gt = 1 + Math.floor(next() * 40);
  } else if (pick === 3) rule.category = next() < 0.5 ? 'scan' : 'policy';
  else if (pick === 4) rule.mode = next() < 0.5 ? 'shadow' : 'live';
  else rule.groupBy = next() < 0.5 ? ['device'] : ['srcIp'];
}

/**
 * @param {any} rule
 * @param {() => number} next
 */
function unsafe(rule, next) {
  const pick = Math.floor(next() * 4);
  if (pick === 0) rule.id = 'Bad Id';
  else if (pick === 1) rule.on = 'nope';
  else if (pick === 2) rule.window = '2m';
  else if (rule.where && rule.where.dstPort) rule.where.dstPort.regex = '.*';
  else delete rule.severity;
}

/**
 * @param {any} rule
 * @param {() => number} next
 */
function mutate(rule, next) {
  const steps = 1 + Math.floor(next() * 3);
  for (let i = 0; i < steps; i += 1) {
    if (next() < 0.8) safe(rule, next);
    else unsafe(rule, next);
  }
  return rule;
}

const engine = createEngine({
  learnMs: 0,
  tiers: ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'],
  shadow: true,
});
let accepted = 0;
let crashes = 0;

for (let i = 0; i < N; i += 1) {
  const base = examples[Math.floor(rng() * examples.length)];
  const rule = mutate(JSON.parse(JSON.stringify(base)), rng);
  let ok = false;
  try {
    engine.loadRules([rule]);
    ok = true;
  } catch (error) {
    if (!(error instanceof Error)) crashes += 1;
  }
  if (!ok) continue;
  accepted += 1;
  try {
    engine.feed({
      type: 'flow',
      device: 'd',
      ts: i,
      srcIp: '10.0.0.8',
      srcPort: 40000,
      dstIp: '1.2.3.4',
      dstPort: 23,
      proto: 'tcp',
      direction: 'out',
      bytesOut: 40,
      bytesIn: 0,
      pktsOut: 1,
      pktsIn: 0,
      durationMs: 10,
    });
  } catch {
    crashes += 1;
  }
}

const ratio = accepted / N;
console.log(
  `rules mutate fuzz: ${N} inputs, ${accepted} accepted (${(ratio * 100).toFixed(2)}%), crashes ${crashes}`,
);
if (crashes > 0 || ratio < 0.5) process.exit(1);
