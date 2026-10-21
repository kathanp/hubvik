'use strict';

const { HubvikError } = require('../errors');

const { FORBIDDEN_KEYS } = require('./constants');
const { assertSafeKeys } = require('./validate');

/**
 * @typedef {'maintenance' | 'firmware-update' | 'user-action' | 'network-change'} AnnotationKind
 */

/**
 * @typedef {{
 *   id: string,
 *   target: string,
 *   kind: AnnotationKind,
 *   fromTs: number,
 *   untilTs: number,
 *   detectors: string[] | null,
 *   note: string | null,
 *   operator: string | null,
 *   suggested: boolean,
 *   addedAt: number,
 * }} Annotation
 */

/**
 * @typedef {{
 *   id: string,
 *   target: string,
 *   kind: AnnotationKind,
 *   fromTs: number,
 *   untilTs: number,
 *   suggested: boolean,
 *   addedAt: number,
 *   detectors?: string[],
 *   note?: string,
 *   operator?: string,
 * }} AnnotationView
 */

/**
 * @typedef {{
 *   next: number,
 *   items: Map<string, Annotation>,
 *   adds: Map<string, number[]>,
 * }} AnnotationBook
 */

/** G3 / D-54. Active rows per target, and the abuse log kept after remove(). */
const DEVICE_CAP = 64;
const STAR_CAP = 256;
const DEVICE_MAX_MS = 72 * 3600e3;
const STAR_MAX_MS = 6 * 3600e3;
const MAX_LEAD_MS = 24 * 3600e3;
const DAY_MS = 24 * 3600e3;
const ABUSE_WINDOW_MS = 7 * DAY_MS;
const DEVICE_ABUSE_COUNT = 10;
const STAR_ABUSE_COUNT = 2;
const MAX_STRING = 255;
const MAX_DETECTORS = 256;
const DETECTOR_ID = /^[a-z0-9-]{1,64}$/;

const NEVER = new Set([
  'threat-intel-match',
  'ot-dangerous-op',
  'ot-value-out-of-range',
  'onvif-config-change',
  'proxy-sdk-traffic',
  'suppression-abuse',
]);

const SPEC_KEYS = new Set(['kind', 'fromTs', 'untilTs', 'detectors', 'note', 'operator']);
const ITEM_KEYS = new Set([
  'id',
  'target',
  'kind',
  'fromTs',
  'untilTs',
  'detectors',
  'note',
  'operator',
  'suggested',
  'addedAt',
]);
const BOOK_KEYS = new Set(['next', 'items', 'adds']);

/**
 * Empty annotation book. Ids are `a1`, `a2`, … and are not reused.
 * @returns {AnnotationBook}
 */
function createAnnotationBook() {
  return { next: 1, items: new Map(), adds: new Map() };
}

/**
 * Record one annotation and return its id.
 * An active window is `[fromTs, untilTs)`. Omitted `detectors` covers every detector
 * this book is allowed to affect. Over a cap or a bad field throws `ANNOTATION_INVALID`
 * and leaves `book` unchanged.
 * @param {AnnotationBook} book
 * @param {string} target device id, or `*`
 * @param {{ kind: string, fromTs: number, untilTs: number, detectors?: string[], note?: string, operator?: string }} spec
 * @param {number} watermark
 * @returns {string}
 */
function add(book, target, spec, watermark) {
  assertBook(book);
  const safeTarget = parseTarget(target);
  const addedAt = parseTime(watermark);
  const fields = parseSpec(spec);
  if (fields.untilTs <= fields.fromTs) invalid();
  assertDuration(safeTarget, fields.fromTs, fields.untilTs);
  if (fields.fromTs < addedAt - MAX_LEAD_MS) invalid();
  const cap = safeTarget === '*' ? STAR_CAP : DEVICE_CAP;
  if (countTarget(book, safeTarget) >= cap) invalid();
  if (!Number.isSafeInteger(book.next) || book.next < 1) invalid();
  const id = `a${book.next}`;
  if (book.items.has(id)) invalid();
  /** @type {Annotation} */
  const item = {
    id,
    target: safeTarget,
    kind: fields.kind,
    fromTs: fields.fromTs,
    untilTs: fields.untilTs,
    detectors: fields.detectors,
    note: fields.note,
    operator: fields.operator,
    suggested: false,
    addedAt,
  };
  book.items.set(id, item);
  remember(book, safeTarget, addedAt);
  book.next += 1;
  return id;
}

/**
 * Drop one annotation. Abuse history for that add stays.
 * @param {AnnotationBook} book
 * @param {string} id
 * @returns {boolean}
 */
function remove(book, id) {
  assertBook(book);
  if (typeof id !== 'string') return false;
  return book.items.delete(id);
}

/**
 * Annotations in insertion order. A device query includes that device and `*`.
 * `activeAt` keeps rows whose window contains that time.
 * @param {AnnotationBook} book
 * @param {{ device?: string, activeAt?: number }} [query]
 * @returns {AnnotationView[]}
 */
function list(book, query) {
  assertBook(book);
  const filter = parseQuery(query);
  /** @type {AnnotationView[]} */
  const out = [];
  for (const item of book.items.values()) {
    if (!matches(item, filter.device, filter.activeAt)) continue;
    out.push(view(item));
  }
  return out;
}

/**
 * True when an active annotation should suppress scoring for this detector.
 * Hard rules are never covered. Neither are threat-intel-match, ot-dangerous-op,
 * ot-value-out-of-range, onvif-config-change, proxy-sdk-traffic, or suppression-abuse.
 * @param {AnnotationBook} book
 * @param {string} device
 * @param {string} detectorId
 * @param {number} ts
 * @param {boolean} hardRule
 * @returns {boolean}
 */
function covers(book, device, detectorId, ts, hardRule) {
  assertBook(book);
  const safeDevice = parseTarget(device);
  if (typeof detectorId !== 'string' || !DETECTOR_ID.test(detectorId)) invalid();
  const at = parseTime(ts);
  if (typeof hardRule !== 'boolean') invalid();
  if (hardRule || NEVER.has(detectorId)) return false;
  for (const item of book.items.values()) {
    if (item.target !== safeDevice && item.target !== '*') continue;
    if (!isActive(item, at)) continue;
    if (item.detectors && !item.detectors.includes(detectorId)) continue;
    return true;
  }
  return false;
}

/**
 * Abuse flags at event time `ts` (not wall-clock time).
 * `deviceSpam` is more than 10 adds for `device` in the 7 days ending at `ts`.
 * `starSpam` is `*` used more than twice on the UTC day of `ts`.
 * @param {AnnotationBook} book
 * @param {string} device
 * @param {number} ts
 * @returns {{ deviceSpam: boolean, starSpam: boolean }}
 */
function abuse(book, device, ts) {
  assertBook(book);
  const safeDevice = parseTarget(device);
  const at = parseTime(ts);
  const start = at - ABUSE_WINDOW_MS;
  let deviceCount = 0;
  const own = book.adds.get(safeDevice);
  if (own) {
    for (const stamp of own) {
      if (stamp >= start && stamp <= at) deviceCount += 1;
    }
  }
  const day = Math.floor(at / DAY_MS);
  let starCount = 0;
  const stars = book.adds.get('*');
  if (stars) {
    for (const stamp of stars) {
      if (Math.floor(stamp / DAY_MS) === day) starCount += 1;
    }
  }
  return {
    deviceSpam: deviceCount > DEVICE_ABUSE_COUNT,
    starSpam: starCount > STAR_ABUSE_COUNT,
  };
}

/**
 * Firmware-update rows that have reached `untilTs` and have not been marked suggested.
 * Reading them does not mark them.
 * @param {AnnotationBook} book
 * @param {number} ts
 * @returns {AnnotationView[]}
 */
function endedFirmware(book, ts) {
  assertBook(book);
  const at = parseTime(ts);
  /** @type {AnnotationView[]} */
  const out = [];
  for (const item of book.items.values()) {
    if (item.kind !== 'firmware-update' || item.suggested || item.untilTs > at) continue;
    out.push(view(item));
  }
  return out;
}

/**
 * Remember that relearn was suggested for this id. Unknown ids return false.
 * @param {AnnotationBook} book
 * @param {string} id
 * @returns {boolean}
 */
function markSuggested(book, id) {
  assertBook(book);
  if (typeof id !== 'string') return false;
  const item = book.items.get(id);
  if (!item) return false;
  item.suggested = true;
  return true;
}

/**
 * Plain snapshot. Does not modify `book`.
 * @param {AnnotationBook} book
 * @returns {{ next: number, items: Annotation[], adds: { target: string, at: number }[] }}
 */
function toJSON(book) {
  assertBook(book);
  /** @type {Annotation[]} */
  const items = [];
  for (const item of book.items.values()) items.push(copyItem(item));
  /** @type {{ target: string, at: number }[]} */
  const adds = [];
  for (const [target, times] of book.adds) {
    for (const at of times) adds.push({ target, at });
  }
  return { next: book.next, items, adds };
}

/**
 * Rebuild a book. The input is fully checked before the book is assembled.
 * @param {unknown} raw
 * @returns {AnnotationBook}
 */
function fromJSON(raw) {
  const row = record(raw, BOOK_KEYS);
  const next = parseNext(row.next);
  const rawItems = asArray(row.items);
  const rawAdds = asArray(row.adds);
  /** @type {Annotation[]} */
  const items = [];
  /** @type {Set<string>} */
  const seen = new Set();
  let maxId = 0;
  for (const entry of rawItems) {
    const item = parseStoredItem(entry, seen);
    const n = Number(item.id.slice(1));
    if (n > maxId) maxId = n;
    items.push(item);
  }
  if (next <= maxId) invalid();
  assertActiveCaps(items);
  /** @type {{ target: string, at: number }[]} */
  const adds = [];
  for (const entry of rawAdds) adds.push(parseAdd(entry));
  assertHistoryCaps(adds);
  /** @type {Map<string, Annotation>} */
  const itemMap = new Map();
  for (const item of items) itemMap.set(item.id, item);
  /** @type {Map<string, number[]>} */
  const addMap = new Map();
  for (const entry of adds) {
    let times = addMap.get(entry.target);
    if (!times) {
      times = [];
      addMap.set(entry.target, times);
    }
    times.push(entry.at);
  }
  return { next, items: itemMap, adds: addMap };
}

/**
 * @returns {never}
 */
function invalid() {
  throw new HubvikError('ANNOTATION_INVALID', 'annotation is invalid');
}

/**
 * @param {unknown} book
 * @returns {asserts book is AnnotationBook}
 */
function assertBook(book) {
  if (!book || typeof book !== 'object' || Array.isArray(book)) invalid();
  const row = /** @type {Record<string, unknown>} */ (book);
  if (!(row.items instanceof Map) || !(row.adds instanceof Map)) invalid();
  if (typeof row.next !== 'number') invalid();
}

/**
 * @param {AnnotationBook} book
 * @param {string} target
 * @returns {number}
 */
function countTarget(book, target) {
  let count = 0;
  for (const item of book.items.values()) {
    if (item.target === target) count += 1;
  }
  return count;
}

/**
 * Keep add times after remove() so abuse can still see them.
 * Each target retains at most its active cap; the oldest stamp drops.
 * @param {AnnotationBook} book
 * @param {string} target
 * @param {number} at
 * @returns {void}
 */
function remember(book, target, at) {
  let times = book.adds.get(target);
  if (!times) {
    times = [];
    book.adds.set(target, times);
  }
  times.push(at);
  const cap = target === '*' ? STAR_CAP : DEVICE_CAP;
  if (times.length > cap) times.shift();
}

/**
 * @param {unknown} spec
 * @returns {{ kind: AnnotationKind, fromTs: number, untilTs: number, detectors: string[] | null, note: string | null, operator: string | null }}
 */
function parseSpec(spec) {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) invalid();
  assertSafeKeys(spec, 'annotation');
  const row = /** @type {Record<string, unknown>} */ (spec);
  for (const key of Object.keys(row)) {
    if (!SPEC_KEYS.has(key)) invalid();
  }
  if (
    !Object.hasOwn(row, 'kind') ||
    !Object.hasOwn(row, 'fromTs') ||
    !Object.hasOwn(row, 'untilTs')
  ) {
    invalid();
  }
  return {
    kind: parseKind(row.kind),
    fromTs: parseTime(row.fromTs),
    untilTs: parseTime(row.untilTs),
    detectors: Object.hasOwn(row, 'detectors') ? parseDetectors(row.detectors) : null,
    note: Object.hasOwn(row, 'note') ? parseText(row.note) : null,
    operator: Object.hasOwn(row, 'operator') ? parseText(row.operator) : null,
  };
}

/**
 * @param {unknown} value
 * @returns {AnnotationKind}
 */
function parseKind(value) {
  if (
    value === 'maintenance' ||
    value === 'firmware-update' ||
    value === 'user-action' ||
    value === 'network-change'
  ) {
    return value;
  }
  invalid();
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function parseTarget(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_STRING) invalid();
  if (FORBIDDEN_KEYS.has(value)) invalid();
  return value;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseTime(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) invalid();
  return value;
}

/**
 * @param {string} target
 * @param {number} fromTs
 * @param {number} untilTs
 * @returns {void}
 */
function assertDuration(target, fromTs, untilTs) {
  const max = target === '*' ? STAR_MAX_MS : DEVICE_MAX_MS;
  if (untilTs - fromTs > max) invalid();
}

/**
 * @param {unknown} value
 * @returns {string[]}
 */
function parseDetectors(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_DETECTORS) invalid();
  /** @type {string[]} */
  const out = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const id of value) {
    if (typeof id !== 'string' || !DETECTOR_ID.test(id) || seen.has(id)) invalid();
    seen.add(id);
    out.push(id);
  }
  return out;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function parseText(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_STRING) invalid();
  return value;
}

/**
 * @param {unknown} query
 * @returns {{ device: string | null, activeAt: number | null }}
 */
function parseQuery(query) {
  if (query == null) return { device: null, activeAt: null };
  if (typeof query !== 'object' || Array.isArray(query)) invalid();
  assertSafeKeys(query, 'annotations');
  const row = /** @type {Record<string, unknown>} */ (query);
  for (const key of Object.keys(row)) {
    if (key !== 'device' && key !== 'activeAt') invalid();
  }
  return {
    device: Object.hasOwn(row, 'device') ? parseTarget(row.device) : null,
    activeAt: Object.hasOwn(row, 'activeAt') ? parseTime(row.activeAt) : null,
  };
}

/**
 * @param {Annotation} item
 * @param {string | null} device
 * @param {number | null} activeAt
 * @returns {boolean}
 */
function matches(item, device, activeAt) {
  if (device != null) {
    if (device === '*') {
      if (item.target !== '*') return false;
    } else if (item.target !== device && item.target !== '*') return false;
  }
  if (activeAt != null && !isActive(item, activeAt)) return false;
  return true;
}

/**
 * @param {Annotation} item
 * @param {number} ts
 * @returns {boolean}
 */
function isActive(item, ts) {
  return ts >= item.fromTs && ts < item.untilTs;
}

/**
 * @param {Annotation} item
 * @returns {AnnotationView}
 */
function view(item) {
  /** @type {AnnotationView} */
  const out = {
    id: item.id,
    target: item.target,
    kind: item.kind,
    fromTs: item.fromTs,
    untilTs: item.untilTs,
    suggested: item.suggested,
    addedAt: item.addedAt,
  };
  if (item.detectors) out.detectors = item.detectors.slice();
  if (item.note != null) out.note = item.note;
  if (item.operator != null) out.operator = item.operator;
  return out;
}

/**
 * @param {Annotation} item
 * @returns {Annotation}
 */
function copyItem(item) {
  return {
    id: item.id,
    target: item.target,
    kind: item.kind,
    fromTs: item.fromTs,
    untilTs: item.untilTs,
    detectors: item.detectors ? item.detectors.slice() : null,
    note: item.note,
    operator: item.operator,
    suggested: item.suggested,
    addedAt: item.addedAt,
  };
}

/**
 * @param {unknown} raw
 * @param {Set<string>} keys
 * @returns {Record<string, unknown>}
 */
function record(raw, keys) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) invalid();
  assertSafeKeys(raw, 'annotations');
  const row = /** @type {Record<string, unknown>} */ (raw);
  for (const key of Object.keys(row)) {
    if (!keys.has(key)) invalid();
  }
  for (const key of keys) {
    if (!Object.hasOwn(row, key)) invalid();
  }
  return row;
}

/**
 * @param {unknown} value
 * @returns {unknown[]}
 */
function asArray(value) {
  if (!Array.isArray(value)) invalid();
  /** @type {unknown[]} */
  const out = [];
  for (let i = 0; i < value.length; i++) out.push(value[i]);
  return out;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseNext(value) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) invalid();
  return value;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function parseId(value) {
  if (typeof value !== 'string' || !/^a[1-9][0-9]*$/.test(value)) invalid();
  const n = Number(value.slice(1));
  if (!Number.isSafeInteger(n) || `a${n}` !== value) invalid();
  return value;
}

/**
 * @param {unknown} raw
 * @param {Set<string>} seen
 * @returns {Annotation}
 */
function parseStoredItem(raw, seen) {
  const row = record(raw, ITEM_KEYS);
  const id = parseId(row.id);
  if (seen.has(id)) invalid();
  seen.add(id);
  const target = parseTarget(row.target);
  const fromTs = parseTime(row.fromTs);
  const untilTs = parseTime(row.untilTs);
  if (untilTs <= fromTs) invalid();
  assertDuration(target, fromTs, untilTs);
  const suggested = row.suggested;
  if (typeof suggested !== 'boolean') invalid();
  const detectors = row.detectors === null ? null : parseDetectors(row.detectors);
  const note = row.note === null ? null : parseText(row.note);
  const operator = row.operator === null ? null : parseText(row.operator);
  return {
    id,
    target,
    kind: parseKind(row.kind),
    fromTs,
    untilTs,
    detectors,
    note,
    operator,
    suggested,
    addedAt: parseTime(row.addedAt),
  };
}

/**
 * @param {unknown} raw
 * @returns {{ target: string, at: number }}
 */
function parseAdd(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) invalid();
  assertSafeKeys(raw, 'annotations');
  const row = /** @type {Record<string, unknown>} */ (raw);
  for (const key of Object.keys(row)) {
    if (key !== 'target' && key !== 'at') invalid();
  }
  if (!Object.hasOwn(row, 'target') || !Object.hasOwn(row, 'at')) invalid();
  return { target: parseTarget(row.target), at: parseTime(row.at) };
}

/**
 * @param {Annotation[]} items
 * @returns {void}
 */
function assertActiveCaps(items) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const item of items) {
    const next = (counts.get(item.target) || 0) + 1;
    const cap = item.target === '*' ? STAR_CAP : DEVICE_CAP;
    if (next > cap) invalid();
    counts.set(item.target, next);
  }
}

/**
 * @param {{ target: string, at: number }[]} adds
 * @returns {void}
 */
function assertHistoryCaps(adds) {
  /** @type {Map<string, number>} */
  const counts = new Map();
  for (const entry of adds) {
    const next = (counts.get(entry.target) || 0) + 1;
    const cap = entry.target === '*' ? STAR_CAP : DEVICE_CAP;
    if (next > cap) invalid();
    counts.set(entry.target, next);
  }
}

module.exports = {
  createAnnotationBook,
  add,
  remove,
  list,
  covers,
  abuse,
  endedFirmware,
  markSuggested,
  toJSON,
  fromJSON,
};
