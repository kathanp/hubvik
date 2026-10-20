'use strict';

const { createEngine, detectors, SEVERITY } = require('hubvik');
const LABEL_MAP = require('./label-map.json');

const DAY = 24 * 60 * 60 * 1000;
const GRACE_MS = 5 * 60 * 1000;
const MERGE_MS = 5 * 60 * 1000;
const Z = 1.96;

/**
 * 95% Wilson score interval for k successes in n trials.
 * @param {number} k
 * @param {number} n
 * @returns {{ low: number, high: number }}
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
 * Count and interval. Fewer than 20 trials is "n too small", with no percentage.
 * @param {number} k
 * @param {number} n
 * @param {string} noun
 * @returns {string}
 */
function formatRate(k, n, noun) {
  if (n === 0) return 'no rate';
  if (n < 20) return `n too small (${k} detected, ${n} ${noun})`;
  return formatWilson(k, n);
}

/**
 * Count and Wilson interval, including samples under 20.
 * @param {number} k
 * @param {number} n
 * @returns {string}
 */
function formatWilson(k, n) {
  if (n <= 0) return 'no rate';
  const interval = wilson(k, n);
  if (!interval) return 'no rate';
  const pct = (value) => (100 * value).toFixed(1);
  return `${k}/${n} = ${pct(k / n)}% (95% Wilson ${pct(interval.low)}%–${pct(interval.high)}%)`;
}

/**
 * Stage or category tokens for a detailed label. Null when the label is unmapped.
 * @param {string} label
 * @returns {Set<string> | null}
 */
function labelTokens(label) {
  const text = String(label || '').toLowerCase();
  if (!text) return null;
  /** @type {Set<string>} */
  const tokens = new Set();
  for (const rule of LABEL_MAP) {
    const hit = rule.match.some((part) => text.includes(String(part).toLowerCase()));
    if (!hit) continue;
    for (const token of rule.tokens) tokens.add(token);
  }
  return tokens.size > 0 ? tokens : null;
}

/**
 * @param {string | null} stage
 * @param {string | null} category
 * @param {Set<string> | null} tokens
 * @returns {boolean}
 */
function mappedHit(stage, category, tokens) {
  if (!tokens) return false;
  if (stage && tokens.has(stage)) return true;
  return Boolean(category && tokens.has(category));
}

/**
 * @param {string} severity
 * @returns {boolean}
 */
function counts(severity) {
  return (SEVERITY[severity] ?? -1) >= SEVERITY.medium;
}

/**
 * Per-device learning prefix. The prefix is the benign events before the first
 * malicious event. A capture with no attack learns 24 h when it has them.
 * @param {any[]} rows
 * @returns {{ learn: any[], rest: any[], learningMs: number, short: boolean }}
 */
function planDevice(rows) {
  const sorted = rows
    .slice()
    .sort((a, b) => a.ts - b.ts || (a.malicious === b.malicious ? 0 : a.malicious ? 1 : -1));
  const firstBad = sorted.find((row) => row.malicious);
  if (!firstBad) {
    if (sorted.length === 0) return { learn: [], rest: [], learningMs: 0, short: true };
    const span = sorted[sorted.length - 1].ts - sorted[0].ts;
    if (span >= DAY) {
      const cut = sorted[0].ts + DAY;
      return {
        learn: sorted.filter((row) => row.ts < cut),
        rest: sorted.filter((row) => row.ts >= cut),
        learningMs: DAY,
        short: false,
      };
    }
    return { learn: sorted, rest: [], learningMs: span, short: true };
  }
  const learn = sorted.filter((row) => row.ts < firstBad.ts);
  const rest = sorted.filter((row) => row.ts >= firstBad.ts);
  const learningMs = learn.length === 0 ? 0 : firstBad.ts - learn[0].ts;
  return { learn, rest, learningMs, short: learningMs < DAY };
}

/**
 * One instance per run of the same detailed-label. A gap above 5 minutes starts another.
 * @param {string} device
 * @param {any[]} rest
 * @returns {any[]}
 */
function attackIntervals(device, rest) {
  /** @type {any[]} */
  const out = [];
  for (const row of rest) {
    if (!row.malicious) continue;
    const prev = out[out.length - 1];
    if (prev && prev.detailedLabel === row.detailedLabel && row.ts - prev.end < MERGE_MS) {
      prev.end = row.ts;
      prev.flows += 1;
      continue;
    }
    out.push({
      device,
      label: row.label,
      detailedLabel: row.detailedLabel,
      start: row.ts,
      end: row.ts,
      flows: 1,
    });
  }
  return out;
}

/**
 * @param {any[]} rows
 * @returns {Map<string, any[]>}
 */
function byDevice(rows) {
  /** @type {Map<string, any[]>} */
  const groups = new Map();
  for (const row of rows) {
    const list = groups.get(row.device);
    if (list) list.push(row);
    else groups.set(row.device, [row]);
  }
  return groups;
}

/**
 * Event types a detector reads. A missing list means every type. An empty list means none.
 * @param {any} det
 * @returns {string[] | null}
 */
function consumesList(det) {
  const raw = det.meta && det.meta.consumes;
  if (raw == null) return null;
  if (!Array.isArray(raw)) return [];
  return raw;
}

/**
 * A dataset can exercise a detector when every required tier is enabled and at
 * least one event has a type that detector consumes.
 * @param {any} det
 * @param {string[]} tiers
 * @param {Set<string>} types
 * @returns {boolean}
 */
function exercised(det, tiers, types) {
  if (!Array.isArray(det.requires) || !det.requires.every((tier) => tiers.includes(tier))) {
    return false;
  }
  const consumes = consumesList(det);
  if (consumes == null) return types.size > 0;
  return consumes.some((type) => types.has(type));
}

/**
 * @param {Map<string, any>} plans
 * @param {string[]} tiers
 * @param {string | null} disabled
 * @param {{ calibratedConfidence?: boolean }} [extra]
 * @returns {any[]}
 */
function replay(plans, tiers, disabled, extra) {
  /** @type {any[]} */
  const anomalies = [];
  for (const [device, plan] of plans) {
    const engine = createEngine({
      learnMs: plan.learn.length === 0 ? 0 : 1e14,
      tiers,
      evidence: false,
      calibratedConfidence: extra != null && extra.calibratedConfidence === true,
      detectors: disabled ? { [disabled]: { enabled: false } } : undefined,
    });
    engine.on('anomaly', (item) => {
      const det = detectors[item.detector];
      anomalies.push({
        detector: item.detector,
        device: item.device,
        ts: item.ts,
        severity: item.severity,
        stage: det && det.meta && det.meta.stage ? det.meta.stage : null,
        category: det && det.category ? det.category : null,
      });
    });
    for (const row of plan.learn) engine.feed(row.event);
    if (plan.learn.length > 0) engine.lock(device);
    const last = plan.rest[plan.rest.length - 1] || plan.learn[plan.learn.length - 1];
    for (const row of plan.rest) engine.feed(row.event);
    if (last) engine.flush(last.ts + 60_000);
  }
  return anomalies;
}

/**
 * @param {any} plan
 * @returns {number}
 */
function lockTs(plan) {
  if (plan.learn.length > 0) return plan.learn[plan.learn.length - 1].ts;
  if (plan.rest.length > 0) return plan.rest[0].ts;
  return 0;
}

/**
 * Anomalies from the post-lock replay. Learning-prefix alerts are not scored.
 * @param {any[]} anomalies
 * @param {Map<string, any>} plans
 * @returns {any[]}
 */
function afterLock(anomalies, plans) {
  return anomalies.filter((item) => {
    const plan = plans.get(item.device);
    if (!plan) return false;
    if (plan.learn.length > 0) return item.ts > lockTs(plan);
    return item.ts >= lockTs(plan);
  });
}

/**
 * @param {any} interval
 * @param {any} item
 * @returns {boolean}
 */
function inDetectionWindow(interval, item) {
  return (
    item.device === interval.device &&
    item.ts >= interval.start &&
    item.ts <= interval.end + GRACE_MS
  );
}

/**
 * @param {any} interval
 * @param {any[]} anomalies
 * @returns {any[]}
 */
function hitsFor(interval, anomalies) {
  return anomalies.filter((item) => counts(item.severity) && inDetectionWindow(interval, item));
}

/**
 * @param {string} severity
 * @param {number} count
 * @param {number} deviceDays
 * @returns {boolean}
 */
function aboveGate(severity, count, deviceDays) {
  if (!(deviceDays > 0) || count <= 0) return false;
  if (severity === 'medium') return count / deviceDays >= 1;
  if (severity === 'high' || severity === 'critical') return count / (deviceDays / 7) >= 1;
  return false;
}

/**
 * @param {Map<string, any>} plans
 * @param {any[]} intervals
 * @returns {number}
 */
function benignDeviceDays(plans, intervals) {
  let ms = 0;
  for (const [device, plan] of plans) {
    if (plan.rest.length === 0) continue;
    const start = plan.rest[0].ts;
    const end = plan.rest[plan.rest.length - 1].ts;
    let span = Math.max(0, end - start);
    for (const interval of intervals) {
      if (interval.device !== device) continue;
      const left = Math.max(interval.start, start);
      const right = Math.min(interval.end, end);
      if (right > left) span -= right - left;
    }
    ms += Math.max(0, span);
  }
  return ms / DAY;
}

/**
 * Benign stretches in the post-lock replay. An attack, or a gap over 5 minutes, splits them.
 * @param {Map<string, any>} plans
 * @param {any[]} intervals
 * @returns {{ device: string, start: number, end: number }[]}
 */
function benignIntervals(plans, intervals) {
  /** @type {{ device: string, start: number, end: number }[]} */
  const out = [];
  for (const [device, plan] of plans) {
    const attacks = intervals.filter((interval) => interval.device === device);
    /** @type {{ device: string, start: number, end: number } | null} */
    let open = null;
    for (const row of plan.rest) {
      if (row.malicious) {
        if (open) out.push(open);
        open = null;
        continue;
      }
      const inside = attacks.some((interval) => row.ts >= interval.start && row.ts <= interval.end);
      if (inside) continue;
      if (open && row.ts - open.end <= MERGE_MS) open.end = row.ts;
      else {
        if (open) out.push(open);
        open = { device, start: row.ts, end: row.ts };
      }
    }
    if (open) out.push(open);
  }
  return out;
}

/**
 * @param {any[]} rows
 * @param {{ tiers: string[], dataset?: string }} opts
 * @returns {any}
 */
function evaluate(rows, opts) {
  const tiers = opts.tiers.slice();
  const plans = new Map();
  /** @type {any[]} */
  const intervals = [];
  /** @type {any[]} */
  const learning = [];
  for (const [device, list] of byDevice(rows)) {
    const plan = planDevice(list);
    plans.set(device, plan);
    learning.push({ device, learningMs: plan.learningMs, short: plan.short });
    for (const interval of attackIntervals(device, plan.rest)) intervals.push(interval);
  }
  const scored = afterLock(replay(plans, tiers, null), plans);
  const instances = intervals.map((interval) => {
    const hits = hitsFor(interval, scored);
    hits.sort((a, b) => a.ts - b.ts);
    const tokens = labelTokens(interval.detailedLabel);
    const strictHits = hits.filter((item) => mappedHit(item.stage, item.category, tokens));
    return {
      ...interval,
      detected: hits.length > 0,
      mapped: tokens != null,
      strictDetected: strictHits.length > 0,
      detectors: [...new Set(hits.map((item) => item.detector))],
      timeToDetectMs: hits.length > 0 ? hits[0].ts - interval.start : null,
    };
  });
  const benign = benignIntervals(plans, intervals);
  const fpItems = scored.filter(
    (item) =>
      counts(item.severity) && !intervals.some((interval) => inDetectionWindow(interval, item)),
  );
  const days = benignDeviceDays(plans, intervals);
  const benignHit = benign.filter((interval) =>
    fpItems.some(
      (item) =>
        item.device === interval.device && item.ts >= interval.start && item.ts <= interval.end,
    ),
  ).length;
  const detected = instances.filter((interval) => interval.detected).length;
  const mappedInstances = instances.filter((interval) => interval.mapped);
  const strictDetected = mappedInstances.filter((interval) => interval.strictDetected).length;
  let learnEvents = 0;
  let maliciousLearnEvents = 0;
  for (const plan of plans.values()) {
    learnEvents += plan.learn.length;
    for (const row of plan.learn) if (row.malicious) maliciousLearnEvents += 1;
  }
  const maliciousLearnShare = learnEvents === 0 ? 0 : maliciousLearnEvents / learnEvents;
  const calibratedScored = afterLock(
    replay(plans, tiers, null, { calibratedConfidence: true }),
    plans,
  );
  const calibratedDetected = intervals.filter(
    (interval) => hitsFor(interval, calibratedScored).length > 0,
  ).length;
  const calibratedFp = calibratedScored.filter(
    (item) =>
      counts(item.severity) && !intervals.some((interval) => inDetectionWindow(interval, item)),
  ).length;
  const byLabel = typeRates(instances);
  /** @type {Set<string>} */
  const types = new Set();
  for (const row of rows) {
    if (row.event && typeof row.event.type === 'string') types.add(row.event.type);
  }
  const ablation = Object.values(detectors)
    .filter((det) => !det.defaults || det.defaults.enabled !== false)
    .filter((det) => !det.meta || det.meta.mode !== 'shadow')
    .map((det) => {
      const id = det.id;
      const severity = (det.defaults && det.defaults.severity) || 'medium';
      if (!exercised(det, tiers, types)) {
        return {
          detector: id,
          severity,
          exercised: false,
          unique: 0,
          falsePositives: 0,
          zeroUnique: false,
          proposal: null,
        };
      }
      const without = afterLock(replay(plans, tiers, id), plans);
      let unique = 0;
      for (const interval of instances) {
        if (!interval.detectors.includes(id)) continue;
        if (hitsFor(interval, without).length === 0) unique += 1;
      }
      const fp = fpItems.filter((item) => item.detector === id).length;
      const propose = unique === 0 && aboveGate(severity, fp, days);
      return {
        detector: id,
        severity,
        exercised: true,
        unique,
        falsePositives: fp,
        zeroUnique: unique === 0,
        proposal: propose
          ? `${id}: zero unique detections and ${fp} ${severity} false positives over ${days} benign device-days, above the C6.3 gate. Proposal: set detectors.${id}.enabled to false, or set severity to info. The human decides.`
          : null,
      };
    });
  return {
    dataset: opts.dataset || null,
    tiers,
    learning,
    learnEvents,
    maliciousLearnEvents,
    maliciousLearnShare,
    poisonedPrefix: maliciousLearnShare > 0,
    attackInstances: instances.length,
    detected,
    detection: formatRate(detected, instances.length, 'attack instances'),
    strictDetected,
    strictInstances: mappedInstances.length,
    strictDetection:
      instances.length > 0 && mappedInstances.length === 0
        ? 'unmapped'
        : formatWilson(strictDetected, mappedInstances.length),
    byLabel,
    misses: instances.filter((interval) => !interval.detected),
    hits: instances.filter((interval) => interval.detected),
    falsePositives: fpItems.length,
    benignDeviceDays: days,
    falsePositivesPerDeviceDay: days > 0 ? fpItems.length / days : null,
    benignIntervals: benign.length,
    benignIntervalsWithFalsePositive: formatRate(benignHit, benign.length, 'benign intervals'),
    ablation,
    proposals: ablation.map((row) => row.proposal).filter(Boolean),
    calibrated: {
      detection: formatRate(calibratedDetected, instances.length, 'attack instances'),
      falsePositives: calibratedFp,
      benignDeviceDays: days,
      falsePositivesPerDeviceDay: days > 0 ? calibratedFp / days : null,
    },
  };
}

/**
 * @param {any} result
 * @returns {string}
 */
function typeRates(instances) {
  /** @type {Map<string, any[]>} */
  const groups = new Map();
  for (const interval of instances) {
    const list = groups.get(interval.detailedLabel) || [];
    list.push(interval);
    groups.set(interval.detailedLabel, list);
  }
  return [...groups.entries()].map(([detailedLabel, list]) => {
    const hits = list.filter((interval) => interval.detected).length;
    const mapped = list.filter((interval) => interval.mapped);
    const strictHits = mapped.filter((interval) => interval.strictDetected).length;
    return {
      detailedLabel,
      detected: hits,
      instances: list.length,
      detection: formatRate(hits, list.length, 'attack instances'),
      strict: mapped.length === 0 ? 'unmapped' : formatWilson(strictHits, mapped.length),
    };
  });
}

/**
 * Stdout lines. The last two are the same rates with `calibratedConfidence` on.
 * @param {any} result
 * @returns {string[]}
 */
function summaryLines(result) {
  const fp =
    result.falsePositivesPerDeviceDay == null
      ? 'no rate'
      : String(result.falsePositivesPerDeviceDay);
  const lines = [
    `dataset: ${result.dataset}`,
    `devices: ${result.learning.length}`,
    `attack instances: ${result.attackInstances}`,
    `detection: ${result.detection}`,
    `FP/device-day: ${fp}`,
  ];
  if (result.calibrated) {
    const calibratedFp =
      result.calibrated.falsePositivesPerDeviceDay == null
        ? 'no rate'
        : String(result.calibrated.falsePositivesPerDeviceDay);
    lines.push(`calibratedConfidence detection: ${result.calibrated.detection}`);
    lines.push(`calibratedConfidence FP/device-day: ${calibratedFp}`);
  }
  return lines;
}

/**
 * @param {any} result
 * @returns {string}
 */
function renderProposals(result) {
  const zeros = result.ablation
    .filter((row) => row.exercised && row.zeroUnique)
    .map((row) => row.detector);
  const lines = [
    '# C6.2 step 6',
    '',
    'The human decides. No default was changed.',
    '',
    '## Zero unique detections',
    '',
  ];
  if (zeros.length === 0) lines.push('None.', '');
  for (const id of zeros) lines.push(`- ${id}`);
  if (zeros.length > 0) lines.push('');
  lines.push('## Proposals', '');
  if (result.proposals.length === 0) lines.push('None.', '');
  for (const proposal of result.proposals) lines.push(`- ${proposal}`);
  if (result.proposals.length > 0) lines.push('');
  return lines.join('\n');
}

/**
 * Learning span and the malicious share of the events actually used for learning.
 * @param {any} result
 * @returns {string[]}
 */
function learningHeader(result) {
  const rows = result.learning || [];
  const same = rows.length > 0 && rows.every((row) => row.learningMs === rows[0].learningMs);
  const span =
    rows.length === 0
      ? 'Learning span: 0 ms.'
      : same
        ? `Learning span: ${rows[0].learningMs} ms.`
        : `Learning span: ${rows.map((row) => `${row.device} ${row.learningMs} ms`).join('; ')}.`;
  const events = result.learnEvents || 0;
  const bad = result.maliciousLearnEvents || 0;
  const share =
    events === 0
      ? 'Malicious-label share inside the learning prefix: 0.'
      : `Malicious-label share inside the learning prefix: ${bad}/${events}.`;
  const lines = [span, '', share, ''];
  if (result.poisonedPrefix) lines.push('POISONED PREFIX', '');
  return lines;
}

/**
 * @param {any} result
 * @returns {string}
 */
function renderMarkdown(result) {
  const short = result.learning.filter((row) => row.short);
  const learningNote =
    short.length === 0
      ? 'Every device learned at least 24 h.'
      : short.map((row) => `${row.device} learned ${row.learningMs} ms (under 24 h)`).join('; ') +
        '.';
  const lines = [
    `# ${result.dataset || 'eval'}`,
    '',
    'Attack intervals: contiguous Malicious runs per (device, detailed-label), merged when the gap is under 5 minutes.',
    '',
    ...(result.dataset === 'ciciot2023' ||
    result.dataset === 'ieee-dataport' ||
    result.dataset === 'ciciomt2024'
      ? ['UNVERIFIED: written from documentation, not run on real data.', '']
      : []),
    ...(result.tiers.length === 1 && result.tiers[0] === 'T1'
      ? ['T1 only (conn.log). DNS, TLS, link-layer and app detectors not exercised.', '']
      : []),
    ...learningHeader(result),
    `Tiers: ${result.tiers.join(', ')}.`,
    '',
    `Learning: ${learningNote}`,
    '',
    `Detection: ${result.detection}`,
    '',
    `Strict detection: ${result.strictDetection == null ? 'no rate' : result.strictDetection}`,
    '',
    `False positives: ${result.falsePositives} anomalies at medium or above, ${result.benignDeviceDays} benign device-days, ${result.falsePositivesPerDeviceDay == null ? 'no rate (0 device-days)' : `${result.falsePositivesPerDeviceDay} per benign device-day`}.`,
    '',
    `Benign intervals with a false positive: ${result.benignIntervalsWithFalsePositive}`,
    '',
    ...(result.calibrated
      ? [
          `calibratedConfidence detection: ${result.calibrated.detection}`,
          '',
          `calibratedConfidence false positives: ${result.calibrated.falsePositives} anomalies at medium or above, ${result.calibrated.benignDeviceDays} benign device-days, ${result.calibrated.falsePositivesPerDeviceDay == null ? 'no rate (0 device-days)' : `${result.calibrated.falsePositivesPerDeviceDay} per benign device-day`}.`,
          '',
        ]
      : []),
    '## By type',
    '',
  ];
  if (!result.byLabel || result.byLabel.length === 0) lines.push('None.', '');
  for (const row of result.byLabel || []) {
    const strict = row.strict == null ? '' : `; strict ${row.strict}`;
    lines.push(`- ${row.detailedLabel}: ${row.detection}${strict}`);
  }
  if (result.byLabel && result.byLabel.length > 0) lines.push('');
  lines.push('## Hits', '');
  if (result.hits.length === 0) lines.push('None.', '');
  for (const hit of result.hits) {
    lines.push(
      `- ${hit.device} ${hit.detailedLabel} at ${hit.start}–${hit.end}, time to detect ${hit.timeToDetectMs} ms, detectors ${hit.detectors.join(', ')}`,
    );
  }
  if (result.hits.length > 0) lines.push('');
  lines.push('## Misses', '');
  if (result.misses.length === 0) lines.push('None.', '');
  for (const miss of result.misses) {
    lines.push(
      `- ${miss.device} ${miss.detailedLabel} at ${miss.start}–${miss.end} (${miss.flows} flows)`,
    );
  }
  if (result.misses.length > 0) lines.push('');
  lines.push('## Ablation', '');
  const exercisedRows = result.ablation.filter((row) => row.exercised);
  if (exercisedRows.length === 0) lines.push('None.', '');
  for (const row of exercisedRows) {
    lines.push(
      `- ${row.detector}: ${row.unique} unique detections, ${row.falsePositives} false positives${row.zeroUnique ? ', zero unique' : ''}`,
    );
  }
  if (exercisedRows.length > 0) lines.push('');
  lines.push('## Not exercised', '');
  const skipped = result.ablation.filter((row) => !row.exercised);
  if (skipped.length === 0) lines.push('None.', '');
  for (const row of skipped) lines.push(`- ${row.detector}`);
  if (skipped.length > 0) lines.push('');
  lines.push('## Proposals', '');
  if (result.proposals.length === 0) lines.push('None. The human decides any later change.', '');
  for (const proposal of result.proposals) lines.push(`- ${proposal}`);
  if (result.proposals.length > 0) lines.push('');
  if (result.evasion) {
    lines.push(
      '## Evasion',
      '',
      'Synthetic known blind spots. Thresholds were not tuned against this suite.',
      '',
    );
    for (const scenario of result.evasion) {
      const who = scenario.detectors.length > 0 ? scenario.detectors.join(', ') : 'none';
      lines.push(
        `- ${scenario.id}: ${scenario.fired ? 'fired' : 'no medium-or-above anomaly'} (${who})`,
      );
    }
    lines.push('');
  }
  return lines.join('\n');
}

module.exports = {
  DAY,
  GRACE_MS,
  MERGE_MS,
  wilson,
  formatRate,
  planDevice,
  attackIntervals,
  aboveGate,
  inDetectionWindow,
  hitsFor,
  evaluate,
  summaryLines,
  formatWilson,
  renderProposals,
  renderMarkdown,
};
