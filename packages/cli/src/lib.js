'use strict';

const { createHmac } = require('node:crypto');

/**
 * Structural check for one declarative rule. No regular expressions.
 * @param {any} rule
 * @param {string} [path]
 * @returns {string[]}
 */
function checkRule(rule, path = '$') {
  /** @type {string[]} */
  const errors = [];
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    return [`${path} must be an object`];
  }
  if (typeof rule.id !== 'string' || !/^[a-z0-9-]+$/.test(rule.id))
    errors.push(`${path}.id is invalid`);
  if (typeof rule.on !== 'string') errors.push(`${path}.on is invalid`);
  const ops = new Set([
    'eq',
    'ne',
    'in',
    'nin',
    'gt',
    'gte',
    'lt',
    'lte',
    'cidr',
    'prefix',
    'suffix',
    'contains',
  ]);
  if (rule.where != null) {
    if (typeof rule.where !== 'object' || Array.isArray(rule.where))
      errors.push(`${path}.where is invalid`);
    else {
      for (const [field, test] of Object.entries(rule.where)) {
        if (!test || typeof test !== 'object') {
          errors.push(`${path}.where.${field} is invalid`);
          continue;
        }
        for (const op of Object.keys(test)) {
          if (!ops.has(op)) errors.push(`${path}.where.${field}.${op} is not an operator`);
        }
      }
    }
  }
  return errors;
}

/**
 * @param {string} eventsJsonl
 * @param {{ createEngine: Function, learnMs?: number, tiers?: string[], lock?: boolean }} opts
 */
function replay(eventsJsonl, opts) {
  const learnMs = opts.learnMs || 0;
  const engine = opts.createEngine({ learnMs, tiers: opts.tiers || ['T0'] });
  /** @type {any[]} */
  const out = [];
  for (const name of ['anomaly', 'shadow-anomaly', 'incident', 'campaign']) {
    engine.on(name, (/** @type {any} */ row) => out.push({ kind: name, ...row }));
  }
  let origin = null;
  let locked = false;
  for (const line of String(eventsJsonl).split('\n')) {
    if (!line.trim()) continue;
    const event = JSON.parse(line);
    if (opts.lock && !locked && origin != null && event.ts >= origin + learnMs) {
      if (typeof engine.lock === 'function') engine.lock();
      locked = true;
    }
    if (origin == null && typeof event.ts === 'number') origin = event.ts;
    engine.feed(event);
  }
  if (typeof engine.flush === 'function') engine.flush();
  return out;
}

/**
 * Enabled tiers with no events, inactive detectors, bad fields, and clock disorder.
 * @param {string} eventsJsonl
 * @param {{ createEngine: Function, tiers?: string[], learnMs?: number }} opts
 */
function doctor(eventsJsonl, opts) {
  const tiers = opts.tiers || ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
  const engine = opts.createEngine({ learnMs: opts.learnMs || 0, tiers });
  let fieldDropped = 0;
  /** @type {string[]} */
  const tiersNeverSeen = [];
  if (typeof engine.on === 'function') {
    engine.on('warning', (/** @type {any} */ warning) => {
      if (warning.code === 'FIELD_DROPPED') fieldDropped += 1;
      if (warning.code === 'TIER_NEVER_SEEN' && warning.message) {
        const tier = String(warning.message).split(' ')[0];
        if (!tiersNeverSeen.includes(tier)) tiersNeverSeen.push(tier);
      }
    });
  }
  let malformed = 0;
  let clockDisorder = 0;
  let reorderMs5000WouldAbsorb = 0;
  let spltEvents = 0;
  let high = null;
  for (const line of String(eventsJsonl).split('\n')) {
    if (!line.trim()) continue;
    /** @type {any} */
    let event;
    try {
      event = JSON.parse(line);
    } catch {
      malformed += 1;
      continue;
    }
    if (!event || typeof event !== 'object' || Array.isArray(event)) {
      malformed += 1;
      continue;
    }
    if (event.splt && typeof event.splt === 'object') spltEvents += 1;
    if (typeof event.ts === 'number' && high != null && event.ts < high) {
      clockDisorder += 1;
      if (high - event.ts <= 5000) reorderMs5000WouldAbsorb += 1;
    }
    if (typeof event.ts === 'number') high = high == null ? event.ts : Math.max(high, event.ts);
    try {
      engine.feed(event);
    } catch {
      malformed += 1;
    }
  }
  const stats = typeof engine.stats === 'function' ? engine.stats() : { detectors: {} };
  /** @type {{ id: string, reason: string | null }[]} */
  const inactive = [];
  for (const [id, status] of Object.entries(stats.detectors || {})) {
    if (status && status.active === false) inactive.push({ id, reason: status.reason || null });
  }
  inactive.sort((a, b) => (a.id < b.id ? -1 : 1));
  return {
    tiersNeverSeen,
    inactive,
    malformed,
    fieldDropped,
    clockDisorder,
    reorderMs5000WouldAbsorb,
    noSplt: spltEvents === 0,
  };
}

/**
 * Self-contained HTML. Timestamps come from the records.
 * @param {string} jsonl
 */
function reportHtml(jsonl) {
  const rows = String(jsonl)
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  /** @type {Record<string, any[]>} */
  const byDevice = {};
  /** @type {Record<string, number>} */
  const counts = {};
  /** @type {any[]} */
  const incidents = [];
  for (const row of rows) {
    const device = String(row.device || 'unknown');
    if (!byDevice[device]) byDevice[device] = [];
    byDevice[device].push(row);
    if (row.detector) counts[row.detector] = (counts[row.detector] || 0) + 1;
    if (row.kind === 'incident' || row.stages) incidents.push(row);
  }
  const timeline = Object.keys(byDevice)
    .sort()
    .map((device) => {
      const items = byDevice[device]
        .map((row) => {
          const explain = row.explain ? `<p>${escapeHtml(String(row.explain))}</p>` : '';
          return `<li>${escapeHtml(String(row.ts || 0))} ${escapeHtml(row.detector || row.kind || '')}${explain}</li>`;
        })
        .join('');
      return `<section><h2>${escapeHtml(device)}</h2><ol>${items}</ol></section>`;
    })
    .join('');
  const top = Object.entries(counts)
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .map(([id, n]) => `<li>${escapeHtml(id)} ${n}</li>`)
    .join('');
  const incidentList = incidents
    .map(
      (row) =>
        `<li>${escapeHtml(String(row.device || ''))} ${escapeHtml(String(row.ts || 0))}</li>`,
    )
    .join('');
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:sans-serif}</style></head><body><h1>Timeline</h1>${timeline}<h1>Incidents</h1><ul>${incidentList}</ul><h1>Detectors</h1><ol>${top}</ol></body></html>`;
}

/**
 * @param {object} a
 * @param {object} b
 */
function diffBaseline(a, b) {
  const left = a && a.devices ? a.devices : {};
  const right = b && b.devices ? b.devices : {};
  /** @type {string[]} */
  const changes = [];
  const ids = new Set([...Object.keys(left), ...Object.keys(right)]);
  for (const id of ids) {
    if (JSON.stringify(left[id]) !== JSON.stringify(right[id])) changes.push(id);
  }
  return changes.sort();
}

/**
 * @param {object} body
 * @param {string | Buffer} key
 */
function verifyBaseline(body, key) {
  if (!body || !body.sig || body.sig.alg !== 'HMAC-SHA256') return false;
  const unsigned = { ...body };
  delete unsigned.sig;
  const mac = createHmac('sha256', key).update(JSON.stringify(unsigned)).digest('hex');
  return mac === body.sig.mac;
}

/**
 * @param {string} value
 */
function escapeHtml(value) {
  return value.replace(
    /[&<>"]/g,
    (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[ch] || ch,
  );
}

module.exports = { checkRule, replay, doctor, reportHtml, diffBaseline, verifyBaseline };
