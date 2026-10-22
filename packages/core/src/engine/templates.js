'use strict';

const { HubvikError } = require('../errors');

const { assertSafeKeys } = require('./validate');

const MAX_TEMPLATES = 64;
const MAX_STEPS = 6;
const MAX_PARTIAL = 1000;
const MAX_WITHIN = 24 * 3600 * 1000;
const KINDS = new Set(['device', 'campaign']);

/**
 * @param {unknown} list
 * @param {Set<string>} known
 * @returns {any[]}
 */
function compile(list, known) {
  if (!Array.isArray(list)) {
    throw new HubvikError('TEMPLATE_INVALID', 'templates must be an array');
  }
  if (list.length > MAX_TEMPLATES) {
    throw new HubvikError('TEMPLATE_INVALID', 'at most 64 templates');
  }
  /** @type {any[]} */
  const out = [];
  const seen = new Set();
  for (const raw of list) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new HubvikError('TEMPLATE_INVALID', 'template must be an object');
    }
    assertSafeKeys(raw, 'template');
    const row = /** @type {any} */ (raw);
    if (
      typeof row.id !== 'string' ||
      row.id.length === 0 ||
      row.id.length > 64 ||
      seen.has(row.id)
    ) {
      throw new HubvikError('TEMPLATE_INVALID', 'template id is invalid');
    }
    seen.add(row.id);
    if (!Array.isArray(row.steps) || row.steps.length === 0 || row.steps.length > MAX_STEPS) {
      throw new HubvikError('TEMPLATE_INVALID', 'template steps are invalid');
    }
    /** @type {{ any: string[], minSeverity: string | null }[]} */
    const steps = [];
    for (const step of row.steps) {
      if (!step || typeof step !== 'object' || Array.isArray(step)) {
        throw new HubvikError('TEMPLATE_INVALID', 'template step is invalid');
      }
      assertSafeKeys(step, 'template step');
      const item = /** @type {any} */ (step);
      const any = Array.isArray(item.any)
        ? item.any
        : typeof item.detector === 'string'
          ? [item.detector]
          : null;
      if (!any || any.length === 0) {
        throw new HubvikError('TEMPLATE_INVALID', 'template step any is invalid');
      }
      for (const id of any) {
        if (typeof id !== 'string' || !known.has(id)) {
          throw new HubvikError('TEMPLATE_INVALID', 'template detector is unknown');
        }
      }
      steps.push({
        any: any.slice(),
        minSeverity: typeof item.minSeverity === 'string' ? item.minSeverity : null,
      });
    }
    const within = parseWithin(row.within);
    const by = row.by == null ? 'device' : row.by;
    if (!KINDS.has(by)) throw new HubvikError('TEMPLATE_INVALID', 'template by is invalid');
    const bonus = row.llrBonus == null ? 0 : row.llrBonus;
    if (typeof bonus !== 'number' || !Number.isFinite(bonus) || bonus < 0 || bonus > 3) {
      throw new HubvikError('TEMPLATE_INVALID', 'template llrBonus is invalid');
    }
    out.push({
      id: row.id,
      steps,
      within,
      by,
      ordered: row.ordered !== false,
      llrBonus: bonus,
      attack: Array.isArray(row.attack) ? row.attack.map(String) : [],
      allowShadow: row.allowShadow === true,
    });
  }
  return out;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseWithin(value) {
  if (typeof value !== 'string' || !/^\d+(m|h)$/.test(value)) {
    throw new HubvikError('TEMPLATE_INVALID', 'template within is invalid');
  }
  const n = Number(value.slice(0, -1));
  const ms = value.endsWith('h') ? n * 3600 * 1000 : n * 60 * 1000;
  if (ms <= 0 || ms > MAX_WITHIN) {
    throw new HubvikError('TEMPLATE_INVALID', 'template within is invalid');
  }
  return ms;
}

/**
 * @returns {{ templates: any[], partials: Map<string, any[]> }}
 */
function createBook() {
  return { templates: [], partials: new Map() };
}

/**
 * Advance every template on one anomaly. Returns matches.
 * @param {{ templates: any[], partials: Map<string, any[]> }} book
 * @param {{ detector: string, device: string, ts: number, id: string, severity?: string, shadow?: boolean, campaignId?: string }} anomaly
 * @returns {{ templateId: string, device: string, anomalyIds: string[], ts: number, shadow: boolean, llrBonus: number }[]}
 */
function advance(book, anomaly) {
  /** @type {{ templateId: string, device: string, anomalyIds: string[], ts: number, shadow: boolean, llrBonus: number }[]} */
  const matches = [];
  for (const template of book.templates) {
    if (anomaly.shadow && !template.allowShadow) continue;
    const key = `${template.id}\0${template.by === 'campaign' ? anomaly.campaignId || anomaly.device : anomaly.device}`;
    let open = book.partials.get(key);
    if (!open) {
      open = [];
      book.partials.set(key, open);
    }
    const step0 = template.steps[0];
    if (matchesStep(step0, anomaly)) {
      if (partialCount(book, template.id) >= MAX_PARTIAL) dropOldest(book, template.id);
      open = book.partials.get(key) || open;
      open.push({
        index: 0,
        ids: [anomaly.id],
        ts: anomaly.ts,
        shadow: Boolean(anomaly.shadow),
        seen: [0],
      });
    }
    /** @type {any[]} */
    const next = [];
    for (const partial of open) {
      if (anomaly.ts - partial.ts > template.within) continue;
      if (template.ordered === false) {
        const used = new Set(partial.seen || [partial.index]);
        let hit = -1;
        if (!partial.ids.includes(anomaly.id)) {
          for (let step = 0; step < template.steps.length; step += 1) {
            if (used.has(step)) continue;
            if (matchesStep(template.steps[step], anomaly)) {
              hit = step;
              break;
            }
          }
        }
        if (hit < 0) {
          next.push(partial);
          continue;
        }
        const ids = partial.ids.concat(anomaly.id);
        const seen = [...used, hit];
        if (seen.length === template.steps.length) {
          matches.push({
            templateId: template.id,
            device: anomaly.device,
            anomalyIds: ids,
            ts: anomaly.ts,
            shadow: partial.shadow || Boolean(anomaly.shadow),
            llrBonus: template.llrBonus,
          });
        } else {
          next.push({
            index: hit,
            ids,
            ts: partial.ts,
            shadow: partial.shadow || Boolean(anomaly.shadow),
            seen,
          });
        }
        continue;
      }
      const want = template.steps[partial.index + 1];
      if (!want || !matchesStep(want, anomaly) || partial.ids.includes(anomaly.id)) {
        next.push(partial);
        continue;
      }
      const ids = partial.ids.concat(anomaly.id);
      if (partial.index + 1 === template.steps.length - 1) {
        matches.push({
          templateId: template.id,
          device: anomaly.device,
          anomalyIds: ids,
          ts: anomaly.ts,
          shadow: partial.shadow || Boolean(anomaly.shadow),
          llrBonus: template.llrBonus,
        });
      } else {
        next.push({
          index: partial.index + 1,
          ids,
          ts: partial.ts,
          shadow: partial.shadow || Boolean(anomaly.shadow),
        });
      }
    }
    book.partials.set(key, next);
  }
  return matches;
}

/**
 * Open partials are capped per template, not per device.
 * @param {{ partials: Map<string, any[]> }} book
 * @param {string} templateId
 * @returns {number}
 */
function partialCount(book, templateId) {
  const prefix = `${templateId}\0`;
  let count = 0;
  for (const [key, list] of book.partials) {
    if (String(key).startsWith(prefix)) count += list.length;
  }
  return count;
}

/**
 * @param {{ partials: Map<string, any[]> }} book
 * @param {string} templateId
 * @returns {void}
 */
function dropOldest(book, templateId) {
  const prefix = `${templateId}\0`;
  for (const [key, list] of book.partials) {
    if (!String(key).startsWith(prefix) || list.length === 0) continue;
    list.shift();
    if (list.length === 0) book.partials.delete(key);
    return;
  }
}

/**
 * @param {{ any: string[], minSeverity: string | null }} step
 * @param {{ detector: string, severity?: string }} anomaly
 * @returns {boolean}
 */
function matchesStep(step, anomaly) {
  if (!step.any.includes(anomaly.detector)) return false;
  if (!step.minSeverity) return true;
  const rank = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return (
    (rank[/** @type {keyof typeof rank} */ (anomaly.severity)] || 0) >=
    (rank[/** @type {keyof typeof rank} */ (step.minSeverity)] || 0)
  );
}

module.exports = { compile, createBook, advance, parseWithin };
