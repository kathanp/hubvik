'use strict';

const ADVICE = require('../data/advice.json');

/**
 * Operator notes for one detector. A missing id returns null. The copy is safe to mutate.
 * @param {string} id
 * @returns {{ meaning: string, check: string[], benignCauses: string[] } | null}
 */
function adviceFor(id) {
  const table =
    /** @type {Record<string, { meaning: string, check: string[], benignCauses?: string[] }>} */ (
      ADVICE
    );
  const row = table[id];
  if (!row || typeof row.meaning !== 'string' || !Array.isArray(row.check)) return null;
  return {
    meaning: row.meaning,
    check: row.check.slice(),
    benignCauses: Array.isArray(row.benignCauses) ? row.benignCauses.slice() : [],
  };
}

module.exports = { adviceFor };
