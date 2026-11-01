'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { LIMITS } = require('./limits.js');

const VERDICTS = new Set(['tp', 'fp', 'benign-true', 'unknown']);

/**
 * @param {any} engine
 * @param {string} stateDir
 * @param {number} now
 * @param {(now: number) => boolean} allow
 * @returns {void}
 */
function applyInbox(engine, stateDir, now, allow) {
  const inbox = path.join(stateDir, 'labels-inbox.jsonl');
  if (!fs.existsSync(inbox)) return;
  const lines = fs.readFileSync(inbox, 'utf8').split('\n').filter(Boolean);
  /** @type {string[]} */
  const left = [];
  for (const line of lines) {
    if (!allow(now)) {
      left.push(line);
      continue;
    }
    applyLine(engine, stateDir, line);
  }
  fs.writeFileSync(inbox, left.length ? `${left.join('\n')}\n` : '');
}

/**
 * @param {any} engine
 * @param {string} stateDir
 * @param {string} line
 * @returns {void}
 */
function applyLine(engine, stateDir, line) {
  let row;
  try {
    row = JSON.parse(line);
  } catch {
    reject(stateDir, line, 'not json');
    return;
  }
  if (!row || !VERDICTS.has(row.verdict) || typeof row.key !== 'string') {
    reject(stateDir, line, 'bad label');
    return;
  }
  try {
    engine.feedback(row.key, row.verdict, { note: row.note });
    fs.appendFileSync(path.join(stateDir, 'labels-applied.jsonl'), `${line}\n`);
  } catch (err) {
    reject(stateDir, line, err instanceof Error ? err.message : 'rejected');
  }
}

/**
 * @param {string} stateDir
 * @param {string} line
 * @param {string} reason
 * @returns {void}
 */
function reject(stateDir, line, reason) {
  fs.appendFileSync(
    path.join(stateDir, 'labels-rejected.jsonl'),
    `${JSON.stringify({ line, reason })}\n`,
  );
}

/**
 * One inbox line. The run process applies it on its inbox interval.
 * @param {string} stateDir
 * @param {{ key: string, verdict: string, note?: string }} row
 * @returns {void}
 */
function queueLabel(stateDir, row) {
  fs.mkdirSync(stateDir, { recursive: true });
  fs.appendFileSync(path.join(stateDir, 'labels-inbox.jsonl'), `${JSON.stringify(row)}\n`);
}

module.exports = { applyInbox, queueLabel, LIMITS };
