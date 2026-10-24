'use strict';

const { HubvikError } = require('../../errors');

const { assertSafeKeys } = require('../validate');

/** Wealth, bets, and payouts are thousandths of 1. 100 is 0.10. */
const WEALTH0 = 100;
const PAYOUT = 40;
const CAP = 64;
const DAY = 86400000;
/** @type {Record<string, number>} */
const WEIGHT = { high: 20, medium: 50, low: 150, info: 400 };
const VERDICTS = new Set(['discover', 'defer']);

/**
 * One device-day of alpha-investing wealth. Foster and Stine, 2008, with the
 * constants in SPEC H1. Wealth never exceeds `WEALTH0` and never goes below 0.
 * @returns {{ wealth: number, day: number | null, decisions: { id: string, verdict: string }[] }}
 */
function createBook() {
  return { wealth: WEALTH0, day: null, decisions: [] };
}

/**
 * Thousandths p-weight for a severity. Critical is not a tested hypothesis.
 * @param {string} severity
 * @returns {number}
 */
function weightOf(severity) {
  if (severity === 'critical') return 0;
  const weight = WEIGHT[severity];
  return weight == null ? WEIGHT.info : weight;
}

/**
 * Spend or restore wealth for one live anomaly. A new UTC day resets the book.
 * A hard rule or a critical anomaly returns `bypass` and does not spend.
 * @param {{ wealth: number, day: number | null, decisions: { id: string, verdict: string }[] }} book
 * @param {{ id: string, severity: string, hardRule?: boolean, ts: number }} row
 * @returns {'bypass' | 'discover' | 'defer'}
 */
function push(book, row) {
  const day = Math.floor(row.ts / DAY);
  if (book.day !== day) {
    book.day = day;
    book.wealth = WEALTH0;
    book.decisions = [];
  }
  if (row.hardRule === true || row.severity === 'critical') return 'bypass';
  const phi = Math.floor(book.wealth / 2);
  const p = weightOf(row.severity);
  const discover = phi > 0 && p <= phi;
  book.wealth = discover
    ? Math.min(WEALTH0, book.wealth - phi + PAYOUT)
    : Math.max(0, book.wealth - phi);
  const verdict = discover ? 'discover' : 'defer';
  book.decisions.push({ id: String(row.id), verdict });
  if (book.decisions.length > CAP) book.decisions.shift();
  return verdict;
}

/**
 * @param {{ wealth: number, day: number | null, decisions: { id: string, verdict: string }[] }} book
 * @returns {{ wealth: number, day: number | null, decisions: { id: string, verdict: string }[] }}
 */
function toJSON(book) {
  return {
    wealth: book.wealth,
    day: book.day,
    decisions: book.decisions.map((row) => ({ id: row.id, verdict: row.verdict })),
  };
}

/**
 * Validate a checkpoint book before the caller installs it.
 * @param {unknown} raw
 * @returns {{ wealth: number, day: number | null, decisions: { id: string, verdict: string }[] }}
 */
function fromJSON(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
  }
  assertSafeKeys(raw, 'fdr');
  const row = /** @type {any} */ (raw);
  if (!Number.isInteger(row.wealth) || row.wealth < 0 || row.wealth > WEALTH0) {
    throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
  }
  if (row.day != null && (!Number.isInteger(row.day) || row.day < 0)) {
    throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
  }
  if (!Array.isArray(row.decisions) || row.decisions.length > CAP) {
    throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
  }
  /** @type {{ id: string, verdict: string }[]} */
  const decisions = [];
  for (const item of row.decisions) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
    }
    assertSafeKeys(item, 'fdr.decisions');
    if (typeof item.id !== 'string' || item.id.length === 0 || item.id.length > 64) {
      throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
    }
    if (!VERDICTS.has(item.verdict)) {
      throw new HubvikError('CHECKPOINT_FDR_IS_INVALID', 'checkpoint fdr is invalid');
    }
    decisions.push({ id: item.id, verdict: item.verdict });
  }
  return { wealth: row.wealth, day: row.day == null ? null : row.day, decisions };
}

module.exports = { CAP, WEALTH0, createBook, push, toJSON, fromJSON };
