'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { LIMITS } = require('./limits.js');
const { writeAtomic } = require('./files.js');

/**
 * @param {any} engine
 * @param {string} stateDir
 * @returns {void}
 */
function restoreNewest(engine, stateDir) {
  const full = listJson(stateDir, 'checkpoint-').sort();
  if (full.length === 0) return;
  const newest = full[full.length - 1];
  const saved = JSON.parse(fs.readFileSync(path.join(stateDir, newest), 'utf8'));
  engine.restore(saved.body);
  const seq = saved.seq || 0;
  for (const name of listJson(stateDir, 'delta-').sort()) {
    const delta = JSON.parse(fs.readFileSync(path.join(stateDir, name), 'utf8'));
    if ((delta.toSeq || 0) <= seq) continue;
    engine.applyDelta(delta.body);
  }
}

/**
 * @param {any} engine
 * @param {string} stateDir
 * @param {number} now
 * @param {{ full: number }} marks
 * @returns {void}
 */
function writeFull(engine, stateDir, now, marks) {
  const body = engine.checkpoint({ createdAt: now });
  writeAtomic(
    path.join(stateDir, `checkpoint-${String(now).padStart(16, '0')}.json`),
    `${JSON.stringify({ seq: engine.stateSeq || 0, body })}\n`,
  );
  marks.full = now;
  const names = listJson(stateDir, 'checkpoint-').sort();
  for (const name of names.slice(0, Math.max(0, names.length - LIMITS.keepFull))) {
    fs.unlinkSync(path.join(stateDir, name));
  }
}

/**
 * @param {any} engine
 * @param {string} stateDir
 * @param {number} now
 * @param {{ delta: number }} marks
 * @returns {void}
 */
function writeDelta(engine, stateDir, now, marks) {
  const body = engine.checkpointDelta(engine._deltaSeq || 0);
  writeAtomic(
    path.join(stateDir, `delta-${String(now).padStart(16, '0')}.json`),
    `${JSON.stringify({ toSeq: body.toSeq, body })}\n`,
  );
  marks.delta = now;
}

/**
 * @param {string} stateDir
 * @param {string} prefix
 * @returns {string[]}
 */
function listJson(stateDir, prefix) {
  if (!fs.existsSync(stateDir)) return [];
  return fs
    .readdirSync(stateDir)
    .filter((name) => name.startsWith(prefix) && name.endsWith('.json'));
}

/**
 * @param {string} stateDir
 * @param {number} now
 * @param {any} event
 * @returns {void}
 */
function appendEvent(stateDir, now, event) {
  const day = new Date(now).toISOString().slice(0, 10);
  const file = path.join(stateDir, 'events', `${day}.jsonl`);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  if (fs.existsSync(file) && fs.statSync(file).size >= LIMITS.eventsBytes) return;
  fs.appendFileSync(file, `${JSON.stringify(event)}\n`);
}

/**
 * @param {string} stateDir
 * @param {number} now
 * @returns {void}
 */
function dropOldEvents(stateDir, now) {
  const dir = path.join(stateDir, 'events');
  if (!fs.existsSync(dir)) return;
  const cutoff = now - LIMITS.keepDays * 24 * 3600e3;
  for (const name of fs.readdirSync(dir)) {
    const day = Date.parse(`${name.slice(0, 10)}T00:00:00Z`);
    if (Number.isFinite(day) && day < cutoff) fs.unlinkSync(path.join(dir, name));
  }
}

module.exports = { restoreNewest, writeFull, writeDelta, appendEvent, dropOldEvents };
