'use strict';

/** Poll, flush, checkpoint, and file caps. D-120 to D-129. */
const LIMITS = {
  pollMs: 1000,
  flushMs: 60 * 1000,
  deltaMs: 300 * 1000,
  fullMs: 6 * 60 * 60 * 1000,
  keepFull: 2,
  keepDays: 35,
  statusMs: 60 * 1000,
  inboxMs: 60 * 1000,
  inboxPerMinute: 1000,
  eventsBytes: 100 * 1024 * 1024,
  labelsForRate: 10,
};

module.exports = { LIMITS };
