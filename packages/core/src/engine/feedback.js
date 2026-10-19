'use strict';

const { assertSafeKeys } = require('./validate');

const CAP = 10_000;
const WEEK = 7 * 24 * 60 * 60 * 1000;
const Z = 1.96;
const VERDICTS = new Set(['tp', 'fp', 'benign-true', 'unknown']);

/**
 * 95% Wilson score interval for k events in n trials.
 * @param {number} k
 * @param {number} n
 * @returns {{ low: number, high: number } | null}
 */
function wilson(k, n) {
  if (n <= 0) return null;
  const p = k / n;
  const z2 = Z * Z;
  const denom = 1 + z2 / n;
  const center = p + z2 / (2 * n);
  const margin = Z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n));
  const low = Math.max(0, (center - margin) / denom);
  const high = Math.min(1, (center + margin) / denom);
  return {
    low: low <= 1e-12 ? 0 : low,
    high: high >= 1 - 1e-12 ? 1 : high,
  };
}

/**
 * Keep the last 10,000 anomalies so feedback can find an id or a fingerprint.
 * @param {any} engine
 * @param {any} anomaly
 * @returns {void}
 */
function rememberAnomaly(engine, anomaly) {
  const meta = {
    id: anomaly.id,
    fingerprint: anomaly.fingerprint,
    detector: anomaly.detector,
    device: anomaly.device,
    ts: anomaly.ts,
  };
  engine._anomalyById.set(meta.id, meta);
  engine._anomalyByFp.set(meta.fingerprint, meta);
  while (engine._anomalyById.size > CAP) {
    const oldest = engine._anomalyById.keys().next().value;
    if (oldest == null) break;
    const row = engine._anomalyById.get(oldest);
    engine._anomalyById.delete(oldest);
    if (row && engine._anomalyByFp.get(row.fingerprint) === row) {
      engine._anomalyByFp.delete(row.fingerprint);
    }
  }
}

/**
 * @param {any} engine
 * @returns {Record<string, { tp: number, fp: number, benign: number, unknown: number, fpRate: number, interval: { low: number, high: number } }>}
 */
function precisionOf(engine) {
  const cut = typeof engine.watermark === 'number' ? engine.watermark - WEEK : -Infinity;
  /** @type {Map<string, { tp: number, fp: number, benign: number, unknown: number }>} */
  const buckets = new Map();
  for (const row of engine._feedback) {
    if (row.ts < cut) continue;
    let bucket = buckets.get(row.detector);
    if (!bucket) {
      bucket = { tp: 0, fp: 0, benign: 0, unknown: 0 };
      buckets.set(row.detector, bucket);
    }
    if (row.verdict === 'tp') bucket.tp += 1;
    else if (row.verdict === 'fp') bucket.fp += 1;
    else if (row.verdict === 'benign-true') bucket.benign += 1;
    else bucket.unknown += 1;
  }
  /** @type {Record<string, any>} */
  const precision = Object.create(null);
  for (const [id, bucket] of buckets) {
    const n = bucket.tp + bucket.fp + bucket.benign + bucket.unknown;
    const fpRate = n === 0 ? 0 : bucket.fp / n;
    precision[id] = {
      tp: bucket.tp,
      fp: bucket.fp,
      benign: bucket.benign,
      unknown: bucket.unknown,
      fpRate,
      interval: wilson(bucket.fp, n) || { low: 0, high: 1 },
    };
  }
  return precision;
}

/**
 * Warn once when a detector's labeled false-positive rate is over 50% on at least 10 labels in 7 days.
 * @param {any} engine
 * @returns {void}
 */
function noteNoisy(engine) {
  const precision = precisionOf(engine);
  for (const [id, row] of Object.entries(precision)) {
    const n = row.tp + row.fp + row.benign + row.unknown;
    if (row.fpRate > 0.5 && n >= 10 && !engine._noisy.has(id)) {
      engine._noisy.add(id);
      engine._warn('NOISY_DETECTOR', 'false-positive rate passed 50% over 7 days', undefined, {
        detector: id,
      });
    }
  }
}

/**
 * Record an operator verdict for an anomaly id or fingerprint.
 * @param {any} engine
 * @param {string} key
 * @param {string} verdict
 * @param {{ operator?: string, note?: string }} [opts]
 * @returns {void}
 */
function recordFeedback(engine, key, verdict, opts) {
  if (typeof key !== 'string' || key.length === 0) throw new TypeError('anomaly id is invalid');
  if (!VERDICTS.has(verdict)) throw new TypeError('verdict is invalid');
  if (opts != null && (typeof opts !== 'object' || Array.isArray(opts))) {
    throw new TypeError('feedback options must be an object');
  }
  if (opts) assertSafeKeys(opts, 'feedback');
  const meta = engine._anomalyById.get(key) || engine._anomalyByFp.get(key);
  if (!meta) throw new TypeError('unknown anomaly');
  /** @type {Record<string, unknown>} */
  const row = {
    fingerprint: meta.fingerprint,
    detector: meta.detector,
    device: meta.device,
    ts: meta.ts,
    verdict,
  };
  if (opts && opts.operator != null) {
    if (
      typeof opts.operator !== 'string' ||
      opts.operator.length === 0 ||
      opts.operator.length > 64
    ) {
      throw new TypeError('operator is invalid');
    }
    row.operator = opts.operator;
  }
  if (opts && opts.note != null) {
    if (typeof opts.note !== 'string' || opts.note.length > 255) {
      throw new TypeError('note is invalid');
    }
    row.note = opts.note;
  }
  engine._feedback.push(row);
  if (engine._feedback.length > CAP) engine._feedback.shift();
  noteNoisy(engine);
}

/**
 * JSONL of the feedback ring. One object per line.
 * @param {any} engine
 * @returns {string}
 */
function labelsOf(engine) {
  const lines = engine._feedback.map((/** @type {any} */ row) => {
    /** @type {Record<string, unknown>} */
    const out = {
      fingerprint: row.fingerprint,
      detector: row.detector,
      device: row.device,
      ts: row.ts,
      verdict: row.verdict,
    };
    if (row.operator) out.operator = row.operator;
    return JSON.stringify(out);
  });
  return lines.length === 0 ? '' : `${lines.join('\n')}\n`;
}

/**
 * Read a checkpoint feedback ring. More than 10,000 rows throws.
 * @param {unknown} raw
 * @returns {any[]}
 */
function readFeedback(raw) {
  if (raw == null) return [];
  if (!Array.isArray(raw)) throw new Error('checkpoint feedback is invalid');
  if (raw.length > CAP) throw new Error('array feedback exceeds cap');
  return raw.map((row) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      throw new Error('checkpoint feedback is invalid');
    }
    assertSafeKeys(row, 'feedback');
    if (
      typeof row.fingerprint !== 'string' ||
      typeof row.detector !== 'string' ||
      typeof row.device !== 'string' ||
      typeof row.ts !== 'number' ||
      !VERDICTS.has(row.verdict)
    ) {
      throw new Error('checkpoint feedback is invalid');
    }
    /** @type {Record<string, unknown>} */
    const out = {
      fingerprint: row.fingerprint,
      detector: row.detector,
      device: row.device,
      ts: row.ts,
      verdict: row.verdict,
    };
    if (row.operator != null) {
      if (typeof row.operator !== 'string') throw new Error('checkpoint feedback is invalid');
      out.operator = row.operator;
    }
    if (row.note != null) {
      if (typeof row.note !== 'string') throw new Error('checkpoint feedback is invalid');
      out.note = row.note;
    }
    return out;
  });
}

module.exports = {
  rememberAnomaly,
  recordFeedback,
  labelsOf,
  precisionOf,
  noteNoisy,
  readFeedback,
  wilson,
};
