'use strict';

const { HubvikError } = require('../errors');

const PATTERNS = require('../data/storage.json');
const { explainThreshold } = require('./lib');

const HOUR = 3600e3;
const TEN_MB = 10 * 1024 * 1024;

const detector = {
  id: 'cloud-storage-exfil',
  version: 1,
  meta: {
    rel: '0.8',
    mode: 'shadow',
    fpRisk: 'Medium',
    consumes: ['flow', 'dns'],
    explains: true,
  },
  requires: ['T1', 'T2'],
  category: 'volume',
  hardRule: false,
  defaults: { enabled: true, severity: 'high', minBytes: TEN_MB, factor: 5 },

  /** @param {any} ev */
  prepare(ev) {
    const name = nameOf(ev);
    return Boolean(name && matchStorage(name));
  },

  createState() {
    return { rows: new Map() };
  },

  /**
   * @param {any} dev
   * @param {any} ev
   */
  learn(dev, ev) {
    note(dev, ev, true, null);
  },

  /**
   * @param {any} dev
   * @param {any} ev
   * @param {any} ctx
   */
  check(dev, ev, ctx) {
    return note(dev, ev, false, ctx);
  },

  /** @param {any} dev */
  exportState(dev) {
    return { rows: [...dev.rows.entries()] };
  },

  /**
   * @param {any} dev
   * @param {any} state
   */
  importState(dev, state) {
    dev.rows = new Map();
    if (!state || !Array.isArray(state.rows)) return;
    if (state.rows.length > PATTERNS.length)
      throw new HubvikError('ARRAY_ROWS_EXCEEDS_CAP', 'array rows exceeds cap');
    for (const pair of state.rows) {
      if (!Array.isArray(pair) || pair.length !== 2 || !pair[1]) continue;
      dev.rows.set(String(pair[0]), {
        seen: Boolean(pair[1].seen),
        hourly: pair[1].hourly || 0,
        samples: pair[1].samples || 0,
        hour: pair[1].hour ?? null,
        hourBytes: pair[1].hourBytes || 0,
        fired: Boolean(pair[1].fired),
      });
    }
  },
};

/**
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} learning
 * @param {any} ctx
 */
function note(dev, ev, learning, ctx) {
  const name = nameOf(ev);
  const pattern = name ? matchStorage(name) : null;
  if (!pattern) return;
  let row = dev.rows.get(pattern);
  if (!row) {
    row = { seen: false, hourly: 0, samples: 0, hour: null, hourBytes: 0, fired: false };
    dev.rows.set(pattern, row);
  }
  if (learning) row.seen = true;
  if (ev.type !== 'flow') return;
  const bytes = ev.bytesOut || 0;
  const hour = Math.floor(ev.ts / HOUR);
  if (row.hour == null) row.hour = hour;
  if (hour !== row.hour) {
    if (learning && row.hourBytes > 0) remember(row);
    row.hour = hour;
    row.hourBytes = 0;
  }
  row.hourBytes += bytes;
  if (learning || row.seen || row.fired) return;
  const learned = row.samples > 0 ? row.hourly / row.samples : 0;
  const bar = Math.max(ctx.options.minBytes, ctx.options.factor * learned);
  if (!(row.hourBytes > bar)) return;
  row.fired = true;
  return {
    severity: ctx.options.severity,
    confidence: 0.8,
    ts: ev.ts,
    actual: `${pattern} ${row.hourBytes}`,
    expected: `<= ${bar} bytes in an hour`,
    explain: explainThreshold({
      test: 'gt',
      observed: row.hourBytes,
      threshold: bar,
      formula: 'max(10 MB, 5 × learned hourly upload)',
    }),
    data: { pattern, bytes: row.hourBytes, name },
  };
}

/**
 * @param {any} row
 */
function remember(row) {
  row.hourly += row.hourBytes;
  row.samples += 1;
}

/**
 * @param {any} ev
 * @returns {string | null}
 */
function nameOf(ev) {
  if (!ev) return null;
  if (ev.type === 'dns' && typeof ev.qname === 'string') return ev.qname;
  if (ev.type === 'flow' && typeof ev.dstName === 'string') return ev.dstName;
  return null;
}

/**
 * Full-name suffix match. A star is one label. The registrable family is not used.
 * @param {string} name
 * @returns {string | null}
 */
function matchStorage(name) {
  const host = name.toLowerCase().replace(/\.$/, '');
  const labels = host.split('.').filter(Boolean);
  for (const pattern of PATTERNS) {
    const parts = pattern.split('.');
    if (labels.length < parts.length) continue;
    const slice = labels.slice(labels.length - parts.length);
    let ok = true;
    for (let i = 0; i < parts.length; i += 1) {
      if (parts[i] !== '*' && slice[i] !== parts[i]) ok = false;
    }
    if (ok) return pattern;
  }
  return null;
}

module.exports = detector;
