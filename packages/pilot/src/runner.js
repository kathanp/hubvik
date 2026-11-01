'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createEngine } = require('hubvik');
const { createParser: conntrackParser } = require('@hubvik/adapter-conntrack');
const { createParser: dnsParser } = require('@hubvik/adapter-dnsmasq');
const { LIMITS } = require('./limits.js');
const { writeAtomic } = require('./files.js');
const { readNewLines, emptyCursor } = require('./follow.js');
const { restoreNewest, writeFull, writeDelta, appendEvent, dropOldEvents } = require('./store.js');
const { applyInbox } = require('./inbox.js');

/**
 * @param {{ stateDir: string, conntrack?: string, dnsmasq?: string }} opts
 */
function createRunner(opts) {
  const stateDir = opts.stateDir;
  fs.mkdirSync(path.join(stateDir, 'events'), { recursive: true });
  const engine = createEngine({
    reorderMs: 5000,
    shadow: true,
    alerts: true,
    learnMs: 7 * 24 * 3600e3,
  });
  let now = 0;
  const conn = conntrackParser({ now: () => now });
  const dns = dnsParser({ now: () => now });
  const cursors = { conntrack: emptyCursor(), dnsmasq: emptyCursor() };
  const marks = { flush: 0, delta: 0, full: 0, status: 0, inbox: 0 };
  const budget = inboxBudget();
  engine.on('anomaly', (event) => appendEvent(stateDir, now, event));
  restoreNewest(engine, stateDir);
  return {
    engine,
    /** @param {number} ts */
    step(ts) {
      now = ts;
      feed(opts.conntrack, cursors.conntrack, conn, engine, ts);
      feed(opts.dnsmasq, cursors.dnsmasq, dns, engine, ts);
      if (ts - marks.flush >= LIMITS.flushMs) {
        engine.flush(ts);
        marks.flush = ts;
      }
      if (ts - marks.delta >= LIMITS.deltaMs) writeDelta(engine, stateDir, ts, marks);
      if (ts - marks.full >= LIMITS.fullMs) writeFull(engine, stateDir, ts, marks);
      if (ts - marks.inbox >= LIMITS.inboxMs) {
        applyInbox(engine, stateDir, ts, budget);
        marks.inbox = ts;
      }
      if (ts - marks.status >= LIMITS.statusMs) writeStatus(engine, stateDir, ts, marks);
      dropOldEvents(stateDir, ts);
    },
    /** @param {number} ts */
    stop(ts) {
      engine.flush(ts);
      writeFull(engine, stateDir, ts, marks);
    },
  };
}

/**
 * @param {string | undefined} file
 * @param {{ offset: number, ino: number | null, partial: string }} cursor
 * @param {{ write: (line: string) => object[] }} parser
 * @param {any} engine
 * @param {number} ts
 */
function feed(file, cursor, parser, engine, ts) {
  if (!file || !fs.existsSync(file)) return;
  for (const line of readNewLines(file, cursor)) {
    for (const event of parser.write(line)) engine.feed({ ...event, ts: event.ts || ts });
  }
}

/**
 * @returns {(now: number) => boolean}
 */
function inboxBudget() {
  let minute = -1;
  let count = 0;
  return (now) => {
    const next = Math.floor(now / 60000);
    if (next !== minute) {
      minute = next;
      count = 0;
    }
    count += 1;
    return count <= LIMITS.inboxPerMinute;
  };
}

/**
 * @param {any} engine
 * @param {string} stateDir
 * @param {number} ts
 * @param {{ status: number }} marks
 */
function writeStatus(engine, stateDir, ts, marks) {
  const stats = engine.stats();
  writeAtomic(
    path.join(stateDir, 'status.json'),
    `${JSON.stringify({ ts, events: stats.events, devices: stats.devices })}\n`,
  );
  marks.status = ts;
}

module.exports = { createRunner };
