'use strict';

const { HubvikError } = require('../errors');

const { FORBIDDEN_KEYS } = require('./constants');
const { assertSafeKeys } = require('./validate');
const {
  createPageHinkley,
  push,
  toJSON: pageToJSON,
  fromJSON: pageFromJSON,
} = require('./stats/pagehinkley');

/** @typedef {ReturnType<typeof createPageHinkley>} PageState */

/**
 * @typedef {'families' | 'bytesOut' | 'ports' | 'hours'} SeriesName
 */

/**
 * One daily series. `count` is the Welford sample count; the caller keeps the
 * Welford and passes σ into `observe`. `day` is the last accepted day index,
 * or -1 before the first sample. `page` is that series' Page–Hinkley state.
 * @typedef {{ count: number, day: number, page: PageState }} DriftSeries
 */

/**
 * @typedef {{
 *   deviceId: string,
 *   families: DriftSeries,
 *   bytesOut: DriftSeries,
 *   ports: DriftSeries,
 *   hours: DriftSeries,
 * }} DriftState
 */

/** @type {readonly SeriesName[]} */
const SERIES = ['families', 'bytesOut', 'ports', 'hours'];

const TOP_KEYS = new Set(['deviceId', 'families', 'bytesOut', 'ports', 'hours']);
const SERIES_KEYS = new Set(['count', 'day', 'page']);

/**
 * Per-device baseline drift (G4 / D-55). Four daily series, each a Page–Hinkley
 * test. This module only returns a crossing. It does not emit warnings.
 * @param {string} deviceId
 * @returns {DriftState}
 */
function createDrift(deviceId) {
  return {
    deviceId: parseDevice(deviceId),
    families: blankSeries(),
    bytesOut: blankSeries(),
    ports: blankSeries(),
    hours: blankSeries(),
  };
}

/**
 * Feed one daily sample. `sigma` is the learning-period Welford population σ
 * (`sqrt(m2 / count)`). Returns the crossing once, then resets that series'
 * test so the same step is not reported on every later sample.
 * The Welford count is not reset.
 * @param {DriftState} state
 * @param {string} series
 * @param {number} value
 * @param {number} dayIndex
 * @param {number} sigma
 * @returns {{ series: SeriesName, direction: 'up' | 'down' } | null}
 */
function observe(state, series, value, dayIndex, sigma) {
  assertDrift(state);
  const name = parseSeriesName(series);
  const sample = parseValue(value);
  const day = parseObserveDay(dayIndex);
  const scale = parseSigma(sigma);
  const row = seriesOf(state, name);
  if (day <= row.day) throw new HubvikError('DRIFT_DAY_IS_INVALID', 'drift day is invalid');
  const page = row.page;
  if (scale === 0) {
    // σ = 0 has no scale. The primitive requires lambda > 0, so use lambda 1
    // and do not treat an alarm as drift. Clear the sticky flag so a later
    // non-zero σ is not reported only because this sample was ignored.
    page.delta = 0;
    page.lambda = 1;
    push(page, sample);
    page.alarmed = false;
    row.count += 1;
    row.day = day;
    return null;
  }
  // D-55: delta = 0.5 σ and lambda = 8 σ.
  page.delta = 0.5 * scale;
  page.lambda = 8 * scale;
  push(page, sample);
  row.count += 1;
  row.day = day;
  const up = page.up - page.upMin;
  const down = page.down - page.downMin;
  if (up <= page.lambda && down <= page.lambda) return null;
  const direction = down > page.lambda && down > up ? 'down' : 'up';
  row.page = createPageHinkley({ delta: page.delta, lambda: page.lambda });
  return { series: name, direction };
}

/**
 * @param {DriftState} state
 * @returns {{ deviceId: string, families: DriftSeries, bytesOut: DriftSeries, ports: DriftSeries, hours: DriftSeries }}
 */
function toJSON(state) {
  assertDrift(state);
  return {
    deviceId: state.deviceId,
    families: seriesToJSON(state.families),
    bytesOut: seriesToJSON(state.bytesOut),
    ports: seriesToJSON(state.ports),
    hours: seriesToJSON(state.hours),
  };
}

/**
 * Rebuild drift state. The payload is checked before the state object is returned.
 * @param {unknown} raw
 * @returns {DriftState}
 */
function fromJSON(raw) {
  const row = record(raw, TOP_KEYS, 'drift');
  const deviceId = parseDevice(row.deviceId);
  const families = parseSeries(row.families);
  const bytesOut = parseSeries(row.bytesOut);
  const ports = parseSeries(row.ports);
  const hours = parseSeries(row.hours);
  return { deviceId, families, bytesOut, ports, hours };
}

/**
 * Placeholder lambda is 1 so the primitive will construct. `observe` replaces
 * delta and lambda from σ before the first push.
 * @returns {DriftSeries}
 */
function blankSeries() {
  return { count: 0, day: -1, page: createPageHinkley({ delta: 0, lambda: 1 }) };
}

/**
 * @param {DriftState} state
 * @param {SeriesName} name
 * @returns {DriftSeries}
 */
function seriesOf(state, name) {
  if (name === 'families') return state.families;
  if (name === 'bytesOut') return state.bytesOut;
  if (name === 'ports') return state.ports;
  return state.hours;
}

/**
 * @param {DriftSeries} row
 * @returns {DriftSeries}
 */
function seriesToJSON(row) {
  return { count: row.count, day: row.day, page: pageToJSON(row.page) };
}

/**
 * @param {unknown} raw
 * @returns {DriftSeries}
 */
function parseSeries(raw) {
  const row = record(raw, SERIES_KEYS, 'drift');
  const count = parseCount(row.count);
  const day = parseStoredDay(row.day);
  if (count === 0 ? day !== -1 : day < 0) {
    throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  return { count, day, page: pageFromJSON(row.page) };
}

/**
 * @param {unknown} state
 * @returns {asserts state is DriftState}
 */
function assertDrift(state) {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  const row = /** @type {Record<string, unknown>} */ (state);
  if (
    !isSeries(row.families) ||
    !isSeries(row.bytesOut) ||
    !isSeries(row.ports) ||
    !isSeries(row.hours)
  ) {
    throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  if (typeof row.deviceId !== 'string' || row.deviceId.length === 0) {
    throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
}

/**
 * @param {unknown} value
 * @returns {value is DriftSeries}
 */
function isSeries(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const row = /** @type {Record<string, unknown>} */ (value);
  return (
    typeof row.count === 'number' &&
    typeof row.day === 'number' &&
    !!row.page &&
    typeof row.page === 'object'
  );
}

/**
 * @param {unknown} raw
 * @param {Set<string>} keys
 * @param {string} path
 * @returns {Record<string, unknown>}
 */
function record(raw, keys, path) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  assertSafeKeys(raw, path);
  const row = /** @type {Record<string, unknown>} */ (raw);
  for (const key of Object.keys(row)) {
    if (!keys.has(key)) throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  for (const key of keys) {
    if (!Object.hasOwn(row, key))
      throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  return row;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
function parseDevice(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) {
    throw new HubvikError('DRIFT_DEVICE_IS_INVALID', 'drift device is invalid');
  }
  if (FORBIDDEN_KEYS.has(value)) {
    throw new HubvikError('DRIFT_DEVICE_IS_INVALID', 'drift device is invalid');
  }
  return value;
}

/**
 * @param {string} name
 * @returns {SeriesName}
 */
function parseSeriesName(name) {
  if (name === 'families' || name === 'bytesOut' || name === 'ports' || name === 'hours')
    return name;
  throw new HubvikError('DRIFT_SERIES_IS_INVALID', 'drift series is invalid');
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseValue(value) {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new HubvikError('DRIFT_VALUE_IS_INVALID', 'drift value is invalid');
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseObserveDay(value) {
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < 0 ||
    value > Number.MAX_SAFE_INTEGER
  ) {
    throw new HubvikError('DRIFT_DAY_IS_INVALID', 'drift day is invalid');
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseStoredDay(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < -1) {
    throw new HubvikError('DRIFT_DAY_IS_INVALID', 'drift day is invalid');
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseCount(value) {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new HubvikError('DRIFT_STATE_IS_INVALID', 'drift state is invalid');
  }
  return value;
}

/**
 * @param {unknown} value
 * @returns {number}
 */
function parseSigma(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new HubvikError('DRIFT_SIGMA_IS_INVALID', 'drift sigma is invalid');
  }
  if (value > 0 && !Number.isFinite(8 * value)) {
    throw new HubvikError('DRIFT_SIGMA_IS_INVALID', 'drift sigma is invalid');
  }
  return value;
}

module.exports = { SERIES, createDrift, observe, toJSON, fromJSON };
