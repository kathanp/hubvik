#!/usr/bin/env node
'use strict';

/**
 * Parse Part B of docs/SPEC.md, compare it to the detector files, and write docs/DETECTORS.md.
 * A row is required in this release when its Rel is a version at or below the core version.
 * Later rows are listed and do not fail the gate.
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const require = createRequire(import.meta.url);
const SPEC = join(ROOT, 'docs/SPEC.md');
const OUT = join(ROOT, 'docs/DETECTORS.md');
const DETECTOR_DIR = join(ROOT, 'packages/core/src/detectors');
const SKIP_FILES = new Set(['index.js', 'lib.js', 'state.js']);
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);

const pkg = JSON.parse(readFileSync(join(ROOT, 'packages/core/package.json'), 'utf8'));
const attackMap = JSON.parse(
  readFileSync(join(ROOT, 'packages/core/src/data/attack-map.json'), 'utf8'),
);
const stages = JSON.parse(readFileSync(join(ROOT, 'packages/core/src/data/stages.json'), 'utf8'));

/**
 * @param {string} message
 */
function fail(message) {
  console.error(`spec-coverage: ${message}`);
  process.exitCode = 1;
}

/**
 * @param {string} line
 * @returns {string[]}
 */
function cells(line) {
  const parts = line.split('|');
  if (line.startsWith('|')) parts.shift();
  if (line.endsWith('|')) parts.pop();
  return parts.map((part) => part.trim());
}

/**
 * @param {string} rel
 * @returns {number | null}
 */
function relValue(rel) {
  const match = /^(\d+)\.(\d+)$/.exec(rel);
  if (!match) return null;
  return Number(match[1]) * 1000 + Number(match[2]);
}

/**
 * @param {string} cell
 * @param {number} count
 * @returns {(string | null)[]}
 */
function severities(cell, count) {
  const plain = cell.replace(/[`*]/g, '').replace(/\s+/g, ' ').trim();
  const parts = plain.split('/').map((part) => part.trim().toLowerCase());
  if (parts.length === count && parts.every((part) => SEVERITIES.has(part))) return parts;
  const named = /default\s+(info|low|medium|high|critical)/i.exec(plain);
  if (named) return Array(count).fill(named[1].toLowerCase());
  if (/^per rule$/i.test(plain)) return Array(count).fill(null);
  if (count === 1 && SEVERITIES.has(plain.toLowerCase())) return [plain.toLowerCase()];
  return Array(count).fill(plain);
}

/**
 * @param {string} markdown
 */
function parseCatalog(markdown) {
  const start = markdown.indexOf('\n# PART B');
  const end = markdown.indexOf('\n# PART C');
  if (start < 0 || end < 0) throw new Error('SPEC.md is missing PART B or PART C');
  const lines = markdown.slice(start, end).split('\n');
  /** @type {{ group: string, id: string, severity: string | null, fpRisk: string, rel: string }[]} */
  const rows = [];
  let group = 'Part B';
  for (let i = 0; i < lines.length; i += 1) {
    const heading = /^##\s+(.+)$/.exec(lines[i]);
    if (heading) group = heading[1].trim();
    if (!lines[i].startsWith('|') || !lines[i + 1] || !/^\|?\s*:?-{3,}/.test(lines[i + 1]))
      continue;
    const header = cells(lines[i]);
    const relAt = header.findIndex((cell) => /^rel$/i.test(cell));
    const idAt = header.findIndex((cell) => /^id$/i.test(cell));
    if (relAt < 0 || idAt !== 0) continue;
    const sevAt = header.findIndex((cell) => /^sev/i.test(cell));
    const fpAt = header.findIndex((cell) => /fp risk/i.test(cell));
    i += 2;
    while (i < lines.length && lines[i].startsWith('|')) {
      const row = cells(lines[i]);
      const ids = [...row[0].matchAll(/`([a-z0-9-]+)`/g)].map((match) => match[1]);
      if (ids.length === 0) {
        i += 1;
        continue;
      }
      const sev = sevAt >= 0 ? severities(row[sevAt] || '', ids.length) : ids.map(() => null);
      const fpRisk = fpAt >= 0 ? (row[fpAt] || '').replace(/\s+/g, ' ').trim() : '';
      const rel = (row[relAt] || '').trim();
      ids.forEach((id, index) => {
        rows.push({ group, id, severity: sev[index], fpRisk, rel });
      });
      i += 1;
    }
    i -= 1;
  }
  return rows;
}

/**
 * @param {string} id
 * @param {string} fpRisk
 * @param {string} rel
 */
function metaSource(id, fpRisk, rel) {
  /** @type {Record<string, unknown>} */
  const meta = { rel, fpRisk };
  if (attackMap[id]) meta.attack = attackMap[id];
  if (stages[id]) meta.stage = stages[id];
  const body = JSON.stringify(meta, null, 2)
    .split('\n')
    .map((line, index) => (index === 0 ? line : `  ${line}`))
    .join('\n');
  return `  meta: ${body},\n`;
}

/**
 * @param {{ id: string, fpRisk: string, rel: string }[]} rows
 */
function stampMissingMeta(rows) {
  const byId = new Map(rows.map((row) => [row.id, row]));
  for (const file of readdirSync(DETECTOR_DIR)) {
    if (!file.endsWith('.js') || SKIP_FILES.has(file)) continue;
    const path = join(DETECTOR_DIR, file);
    const source = readFileSync(path, 'utf8');
    if (source.includes('\n  meta:')) continue;
    const id = file.slice(0, -3);
    const row = byId.get(id);
    if (!row) continue;
    const next = source.replace(
      /\n {2}version: \d+,\n/,
      (line) => `${line}${metaSource(id, row.fpRisk, row.rel)}`,
    );
    if (next === source) fail(`${file} has no version line to attach meta`);
    else writeFileSync(path, next);
  }
}

const rows = parseCatalog(readFileSync(SPEC, 'utf8'));
const seen = new Map();
for (const row of rows) {
  if (seen.has(row.id)) fail(`${row.id} appears in more than one Part B row`);
  seen.set(row.id, row);
}

if (process.argv.includes('--stamp-meta')) stampMissingMeta(rows);

/** @type {Map<string, any>} */
const code = new Map();
for (const file of readdirSync(DETECTOR_DIR)) {
  if (!file.endsWith('.js') || SKIP_FILES.has(file)) continue;
  const loaded = require(join(DETECTOR_DIR, file));
  if (!loaded || typeof loaded.id !== 'string') continue;
  if (loaded.id !== file.slice(0, -3)) {
    fail(`${file} does not export a detector whose id matches the file name`);
    continue;
  }
  code.set(loaded.id, loaded);
}

const coreRel = relValue(pkg.version.split('.').slice(0, 2).join('.'));
if (coreRel == null) fail(`core version ${pkg.version} is not x.y.z`);

/** @type {string[]} */
const pending = [];
/** @type {Map<string, typeof rows>} */
const groups = new Map();

for (const row of rows) {
  const list = groups.get(row.group) || [];
  list.push(row);
  groups.set(row.group, list);
  const due = relValue(row.rel);
  const detector = code.get(row.id);
  if ((due == null || (coreRel != null && due > coreRel)) && !detector) {
    pending.push(`- \`${row.id}\` — Rel ${row.rel}, not yet implemented`);
    continue;
  }
  if (!detector) {
    fail(`${row.id} is Rel ${row.rel} and has no detector file`);
    continue;
  }
  const meta = detector.meta || {};
  if (meta.rel !== row.rel)
    fail(`${row.id} meta.rel is ${meta.rel || 'missing'}, row says ${row.rel}`);
  if (
    row.severity &&
    SEVERITIES.has(row.severity) &&
    detector.defaults &&
    detector.defaults.severity !== row.severity
  ) {
    fail(`${row.id} severity is ${detector.defaults.severity}, row says ${row.severity}`);
  }
}

for (const [id, detector] of code) {
  if (!seen.has(id)) fail(`${id} has a detector file and no Part B row`);
  if (!detector.meta || typeof detector.meta.rel !== 'string') fail(`${id} is missing meta.rel`);
}

const lines = [
  '# Detectors',
  '',
  `Generated by \`scripts/spec-coverage.mjs\` from Part B of \`docs/SPEC.md\` and the detector files. Core ${pkg.version}. Do not edit by hand.`,
  '',
];

for (const [group, list] of groups) {
  lines.push(`## ${group}`, '');
  lines.push('| ID | Rel | Severity | FP risk | In this release |');
  lines.push('| --- | --- | --- | --- | --- |');
  for (const row of list) {
    const due = relValue(row.rel);
    const shipped = due != null && coreRel != null && due <= coreRel ? 'yes' : 'no';
    const severity = row.severity || 'per rule';
    lines.push(
      `| \`${row.id}\` | ${row.rel} | ${severity} | ${row.fpRisk.replace(/\|/g, '/')} | ${shipped} |`,
    );
  }
  lines.push('');
}

lines.push('## Not yet implemented', '');
lines.push(...pending);
lines.push('');
lines.push('## Counts', '');
lines.push('| Group | Rows |');
lines.push('| --- | --- |');
for (const [group, list] of groups) lines.push(`| ${group} | ${list.length} |`);
lines.push(`| Total | ${rows.length} |`);
lines.push('');

writeFileSync(OUT, lines.join('\n'));
execFileSync(join(ROOT, 'node_modules/.bin/prettier'), ['--write', OUT], { stdio: 'ignore' });

if (!process.exitCode) {
  console.log(
    `spec-coverage: ${rows.length} rows, ${code.size} detector files, core ${pkg.version}`,
  );
  for (const line of pending) {
    if (line.includes('Rel 0.5')) console.log(line.replace(/^- /, 'pending: '));
  }
  console.log('spec-coverage: ok');
}
