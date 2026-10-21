'use strict';

const { HubvikError } = require('../errors');

const { assertSafeKeys } = require('./validate');
const { ipv4, inBlock } = require('./net');
const { createHll, add, count, toJSON, fromJSON } = require('./stats/hll');
const { explainMatch } = require('../detectors/lib');

const RULE_CAP = 256;
const GROUP_CAP = 10_000;
const DISTINCT_EXACT = 1_000;
const PARTIAL_CAP = 1_000;
const STEP_CAP = 4;
const VALUE_CAP = 64;
const OPS = new Set([
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
const WINDOWS = { '1m': 60_000, '5m': 300_000, '10m': 600_000, '1h': 3_600_000, '24h': 86_400_000 };
const TIER_OF = {
  summary: 'T0',
  flow: 'T1',
  mapping: 'T1',
  dns: 'T2',
  tls: 'T3',
  http: 'T3',
  arp: 'T4',
  dhcp: 'T4',
  ra: 'T4',
  discovery: 'T4',
  nd: 'T4',
  wifi: 'T4',
  app: 'T5',
};
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);

/**
 * Validate every rule, then return compiled detectors. Throws before any detector is returned.
 * @param {unknown} input
 * @param {number} windowMs
 * @returns {any[]}
 */
function compileRules(input, windowMs) {
  if (!Array.isArray(input))
    throw new HubvikError('RULES_MUST_BE_AN_ARRAY', 'rules must be an array');
  if (input.length > RULE_CAP)
    throw new HubvikError('ARRAY_RULES_EXCEEDS_CAP', 'array rules exceeds cap');
  const seen = new Set();
  /** @type {any[]} */
  const out = [];
  for (let i = 0; i < input.length; i += 1) {
    const spec = normalizeRule(input[i], i, windowMs);
    if (seen.has(spec.id))
      throw new HubvikError('RULES_ID_IS_DUPLICATED', `rules[${i}].id is duplicated`);
    seen.add(spec.id);
    out.push(compileDetector(spec));
  }
  return out;
}

/**
 * @param {unknown} raw
 * @param {number} index
 * @param {number} windowMs
 */
function normalizeRule(raw, index, windowMs) {
  const path = `rules[${index}]`;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
  assertSafeKeys(raw, path);
  const rule = /** @type {any} */ (raw);
  if (typeof rule.id !== 'string' || !/^[a-z0-9-]+$/.test(rule.id)) {
    throw new HubvikError('ID_IS_INVALID', `${path}.id is invalid`);
  }
  const mode = rule.mode == null ? 'shadow' : rule.mode;
  if (mode !== 'shadow' && mode !== 'live')
    throw new HubvikError('MODE_IS_INVALID', `${path}.mode is invalid`);
  if (!SEVERITIES.has(rule.severity))
    throw new HubvikError('SEVERITY_IS_INVALID', `${path}.severity is invalid`);
  const category = rule.category == null ? 'policy' : rule.category;
  if (typeof category !== 'string' || category.length === 0 || category.length > 32) {
    throw new HubvikError('CATEGORY_IS_INVALID', `${path}.category is invalid`);
  }
  const sequence =
    rule.sequence == null ? null : normalizeSequence(rule.sequence, rule, path, windowMs);
  const on = sequence ? null : requireType(rule.on, `${path}.on`);
  const where = sequence ? null : normalizeWhere(rule.where, `${path}.where`);
  const window = sequence
    ? sequence.within
    : normalizeWindow(rule.window, `${path}.window`, windowMs);
  return {
    id: rule.id,
    mode,
    severity: rule.severity,
    category,
    fpRisk: typeof rule.fpRisk === 'string' ? rule.fpRisk : '',
    on,
    where,
    window,
    groupBy: normalizeGroupBy(rule.groupBy, path),
    agg: sequence ? null : normalizeAgg(rule.agg, path),
    when: sequence ? null : normalizeWhen(rule.when, path),
    sequence,
    consumes: sequence ? sequence.consumes : [on],
    requires: sequence ? sequence.requires : [TIER_OF[/** @type {keyof typeof TIER_OF} */ (on)]],
    baselineFields: sequence ? [] : baselineFields(where),
  };
}

/**
 * @param {unknown} value
 * @param {string} path
 */
function requireType(value, path) {
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(TIER_OF, value)) {
    throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} path
 * @param {number} engineWindow
 */
function normalizeWindow(value, path, engineWindow) {
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(WINDOWS, value)) {
    throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
  }
  const ms = WINDOWS[/** @type {keyof typeof WINDOWS} */ (value)];
  if (engineWindow <= 0 || ms % engineWindow !== 0)
    throw new HubvikError('IS_NOT_A_MULTIPLE_OF_WINDOWMS', `${path} is not a multiple of windowMs`);
  return ms;
}

/**
 * @param {unknown} steps
 * @param {any} rule
 * @param {string} path
 * @param {number} windowMs
 */
function normalizeSequence(steps, rule, path, windowMs) {
  if (!Array.isArray(steps) || steps.length < 2 || steps.length > STEP_CAP) {
    throw new HubvikError('SEQUENCE_IS_INVALID', `${path}.sequence is invalid`);
  }
  const by = rule.by == null ? 'device' : rule.by;
  if (by !== 'device' && by !== 'srcIp')
    throw new HubvikError('BY_IS_INVALID', `${path}.by is invalid`);
  const within = normalizeWindow(rule.within, `${path}.within`, windowMs);
  /** @type {string[]} */
  const consumes = [];
  /** @type {string[]} */
  const requires = [];
  const compiled = steps.map((step, index) => {
    const stepPath = `${path}.sequence[${index}]`;
    if (!step || typeof step !== 'object' || Array.isArray(step))
      throw new HubvikError('IS_INVALID_2', `${stepPath} is invalid`);
    assertSafeKeys(step, stepPath);
    const row = /** @type {any} */ (step);
    const on = requireType(row.on, `${stepPath}.on`);
    if (!consumes.includes(on)) consumes.push(on);
    const tier = TIER_OF[/** @type {keyof typeof TIER_OF} */ (on)];
    if (!requires.includes(tier)) requires.push(tier);
    return { on, where: normalizeWhere(row.where, `${stepPath}.where`) };
  });
  return { steps: compiled, by, within, consumes, requires };
}

/**
 * @param {unknown} where
 * @param {string} path
 */
function normalizeWhere(where, path) {
  if (where == null) return [];
  if (!where || typeof where !== 'object' || Array.isArray(where))
    throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
  assertSafeKeys(where, path);
  /** @type {{ field: string, baseline: boolean, ops: { op: string, value: any }[] }[]} */
  const fields = [];
  for (const [field, pred] of Object.entries(where)) {
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(field))
      throw new HubvikError('IS_INVALID_3', `${path}.${field} is invalid`);
    if (!pred || typeof pred !== 'object' || Array.isArray(pred))
      throw new HubvikError('IS_INVALID_3', `${path}.${field} is invalid`);
    assertSafeKeys(pred, `${path}.${field}`);
    /** @type {{ op: string, value: any }[]} */
    const ops = [];
    let baseline = false;
    for (const [op, value] of Object.entries(pred)) {
      if (op === 'baseline') {
        if (value !== true)
          throw new HubvikError('BASELINE_IS_INVALID', `${path}.${field}.baseline is invalid`);
        baseline = true;
        continue;
      }
      if (!OPS.has(op)) throw new HubvikError('IS_INVALID_4', `${path}.${field}.${op} is invalid`);
      ops.push({ op, value: normalizeOperand(op, value, `${path}.${field}.${op}`) });
    }
    fields.push({ field, baseline, ops });
  }
  return fields;
}

/**
 * @param {string} op
 * @param {any} value
 * @param {string} path
 */
function normalizeOperand(op, value, path) {
  if (op === 'in' || op === 'nin') {
    if (!Array.isArray(value) || value.length === 0 || value.length > VALUE_CAP)
      throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
    return value.map((item) => scalar(item, path));
  }
  if (op === 'cidr') {
    if (typeof value !== 'string' || value.length > VALUE_CAP)
      throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
    const slash = value.indexOf('/');
    const ip = ipv4(value.slice(0, slash));
    const bits = Number(value.slice(slash + 1));
    if (ip == null || !Number.isInteger(bits) || bits < 0 || bits > 32)
      throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
    return { base: ip, bits };
  }
  if (op === 'prefix' || op === 'suffix' || op === 'contains') {
    if (typeof value !== 'string' || value.length === 0 || value.length > VALUE_CAP) {
      throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
    }
    return value;
  }
  return scalar(value, path);
}

/**
 * @param {any} value
 * @param {string} path
 */
function scalar(value, path) {
  if (typeof value === 'string') {
    if (value.length > 255) throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
    return value;
  }
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'boolean') return value;
  throw new HubvikError('IS_INVALID_2', `${path} is invalid`);
}

/**
 * @param {unknown} groupBy
 * @param {string} path
 */
function normalizeGroupBy(groupBy, path) {
  const list = groupBy == null ? ['device'] : groupBy;
  if (!Array.isArray(list) || list.length === 0 || list.length > 4)
    throw new HubvikError('GROUPBY_IS_INVALID', `${path}.groupBy is invalid`);
  return list.map((field) => {
    if (typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9]*$/.test(field)) {
      throw new HubvikError('GROUPBY_IS_INVALID', `${path}.groupBy is invalid`);
    }
    return field;
  });
}

/**
 * @param {unknown} agg
 * @param {string} path
 */
function normalizeAgg(agg, path) {
  if (agg == null) return [];
  if (!agg || typeof agg !== 'object' || Array.isArray(agg))
    throw new HubvikError('AGG_IS_INVALID', `${path}.agg is invalid`);
  assertSafeKeys(agg, `${path}.agg`);
  /** @type {{ name: string, kind: string, field: string | null }[]} */
  const out = [];
  for (const [name, spec] of Object.entries(agg)) {
    if (!/^[A-Za-z][A-Za-z0-9]*$/.test(name))
      throw new HubvikError('AGG_IS_INVALID_2', `${path}.agg.${name} is invalid`);
    if (spec === 'count') out.push({ name, kind: 'count', field: null });
    else if (spec && typeof spec === 'object' && !Array.isArray(spec)) {
      assertSafeKeys(spec, `${path}.agg.${name}`);
      const keys = Object.keys(spec);
      if (keys.length !== 1)
        throw new HubvikError('AGG_IS_INVALID_2', `${path}.agg.${name} is invalid`);
      const kind = keys[0];
      if (
        kind !== 'count' &&
        kind !== 'sum' &&
        kind !== 'max' &&
        kind !== 'min' &&
        kind !== 'distinct'
      ) {
        throw new HubvikError('AGG_IS_INVALID_2', `${path}.agg.${name} is invalid`);
      }
      const field = kind === 'count' ? null : spec[kind];
      if (
        kind !== 'count' &&
        (typeof field !== 'string' || !/^[A-Za-z][A-Za-z0-9]*$/.test(field))
      ) {
        throw new HubvikError('AGG_IS_INVALID_2', `${path}.agg.${name} is invalid`);
      }
      out.push({ name, kind, field });
    } else throw new HubvikError('AGG_IS_INVALID_2', `${path}.agg.${name} is invalid`);
  }
  return out;
}

/**
 * @param {unknown} when
 * @param {string} path
 */
function normalizeWhen(when, path) {
  if (when == null) return [];
  if (!when || typeof when !== 'object' || Array.isArray(when))
    throw new HubvikError('WHEN_IS_INVALID', `${path}.when is invalid`);
  assertSafeKeys(when, `${path}.when`);
  /** @type {{ name: string, op: string, value: number }[]} */
  const out = [];
  for (const [name, pred] of Object.entries(when)) {
    if (!pred || typeof pred !== 'object' || Array.isArray(pred))
      throw new HubvikError('WHEN_IS_INVALID_2', `${path}.when.${name} is invalid`);
    assertSafeKeys(pred, `${path}.when.${name}`);
    const keys = Object.keys(pred);
    if (keys.length !== 1 || !['gt', 'gte', 'lt', 'lte', 'eq'].includes(keys[0])) {
      throw new HubvikError('WHEN_IS_INVALID_2', `${path}.when.${name} is invalid`);
    }
    const value = pred[keys[0]];
    if (typeof value !== 'number' || !Number.isFinite(value))
      throw new HubvikError('WHEN_IS_INVALID_2', `${path}.when.${name} is invalid`);
    out.push({ name, op: keys[0], value });
  }
  return out;
}

/**
 * @param {{ field: string, baseline: boolean }[] | null} where
 */
function baselineFields(where) {
  return (where || []).filter((field) => field.baseline).map((field) => field.field);
}

/**
 * @param {any} spec
 */
function compileDetector(spec) {
  return {
    id: `rule:${spec.id}`,
    version: 1,
    meta: {
      rel: '0.8',
      mode: spec.mode,
      fpRisk: spec.fpRisk,
      consumes: spec.consumes,
      explains: false,
    },
    requires: spec.requires,
    category: spec.category,
    hardRule: false,
    defaults: { enabled: true, severity: spec.severity },
    createState() {
      return { groups: new Map(), partials: [], learned: {} };
    },
    /** @param {any} dev @param {any} ev */
    learn(dev, ev) {
      observe(spec, dev, ev, true);
    },
    /** @param {any} dev @param {any} ev @param {any} ctx */
    check(dev, ev, ctx) {
      return observe(spec, dev, ev, false, ctx);
    },
    /** @param {any} dev */
    exportState(dev) {
      return {
        learned: dev.learned,
        partials: dev.partials.slice(),
        groups: [...dev.groups.entries()],
      };
    },
    /** @param {any} dev @param {any} state */
    importState(dev, state) {
      importRuleState(dev, state);
    },
    /** @param {any} dev */
    memoryEstimate(dev) {
      return (dev.groups.size + dev.partials.length) * 64;
    },
  };
}

/**
 * @param {any} spec
 * @param {any} dev
 * @param {any} ev
 * @param {boolean} learning
 * @param {any} [ctx]
 */
function observe(spec, dev, ev, learning, ctx) {
  if (!ev || !spec.consumes.includes(ev.type)) return;
  if (spec.sequence) return learning ? undefined : matchSequence(spec, dev, ev, ctx);
  if (!matchesWhere(ev, spec.where, dev.learned, false)) return;
  if (learning) {
    rememberBaseline(spec, dev, ev);
    return;
  }
  if (!matchesWhere(ev, spec.where, dev.learned, true)) return;
  const group = touchGroup(dev, groupKey(ev, spec.groupBy), spec.window, ev.ts);
  const values = applyAgg(group, spec.agg, ev);
  if (group.fired) return;
  if (spec.agg.length > 0 && !whenHolds(spec.when, values)) return;
  group.fired = true;
  return draft(spec, ev, ctx, values);
}

/**
 * @param {any} spec
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function matchSequence(spec, dev, ev, ctx) {
  const steps = spec.sequence.steps;
  const key = spec.sequence.by === 'srcIp' ? ev.srcIp : ev.device;
  if (typeof key !== 'string') return;
  for (let i = steps.length - 1; i >= 1; i -= 1) {
    if (ev.type !== steps[i].on || !matchesWhere(ev, steps[i].where, dev.learned, true)) continue;
    const hit = dev.partials.findIndex(
      (/** @type {any} */ row) =>
        row.next === i &&
        row.key === key &&
        ev.ts - row.ts <= spec.sequence.within &&
        ev.ts >= row.ts,
    );
    if (hit < 0) continue;
    const row = dev.partials.splice(hit, 1)[0];
    if (i === steps.length - 1) return draft(spec, ev, ctx, {});
    row.next = i + 1;
    row.ts = ev.ts;
    dev.partials.push(row);
    return;
  }
  if (ev.type === steps[0].on && matchesWhere(ev, steps[0].where, dev.learned, true)) {
    dev.partials.push({ key, ts: ev.ts, next: 1 });
    while (dev.partials.length > PARTIAL_CAP) dev.partials.shift();
  }
}

/**
 * @param {any} ev
 * @param {{ field: string, baseline: boolean, ops: { op: string, value: any }[] }[]} where
 * @param {Record<string, string[]>} learned
 * @param {boolean} useBaseline
 */
function matchesWhere(ev, where, learned, useBaseline) {
  for (const field of where) {
    const value = ev[field.field];
    if (useBaseline && field.baseline) {
      const known = learned[field.field] || [];
      if (known.includes(String(value))) return false;
    }
    for (const op of field.ops) {
      if (!opHolds(op.op, value, op.value)) return false;
    }
  }
  return true;
}

/**
 * @param {string} op
 * @param {any} value
 * @param {any} expected
 */
function opHolds(op, value, expected) {
  if (op === 'eq') return value === expected;
  if (op === 'ne') return value !== expected;
  if (op === 'in') return expected.includes(value);
  if (op === 'nin') return !expected.includes(value);
  if (op === 'gt') return typeof value === 'number' && value > expected;
  if (op === 'gte') return typeof value === 'number' && value >= expected;
  if (op === 'lt') return typeof value === 'number' && value < expected;
  if (op === 'lte') return typeof value === 'number' && value <= expected;
  if (op === 'cidr') {
    const ip = typeof value === 'string' ? ipv4(value) : null;
    return ip != null && inBlock(ip, expected.base, expected.bits);
  }
  if (typeof value !== 'string') return false;
  if (op === 'prefix') return value.startsWith(expected);
  if (op === 'suffix') return value.endsWith(expected);
  return value.includes(expected);
}

/**
 * @param {any} spec
 * @param {any} dev
 * @param {any} ev
 */
function rememberBaseline(spec, dev, ev) {
  for (const field of spec.baselineFields) {
    const value = ev[field];
    if (value == null) continue;
    const text = String(value);
    const list = dev.learned[field] || [];
    if (!list.includes(text) && list.length < DISTINCT_EXACT) list.push(text);
    dev.learned[field] = list;
  }
}

/**
 * @param {any} ev
 * @param {string[]} fields
 */
function groupKey(ev, fields) {
  return fields.map((field) => String(ev[field] ?? '')).join('|');
}

/**
 * @param {any} dev
 * @param {string} key
 * @param {number} windowMs
 * @param {number} ts
 */
function touchGroup(dev, key, windowMs, ts) {
  const start = ts - (ts % windowMs);
  let group = dev.groups.get(key);
  if (group && group.start === start) {
    dev.groups.delete(key);
    dev.groups.set(key, group);
    return group;
  }
  while (!group && dev.groups.size >= GROUP_CAP) {
    const oldest = dev.groups.keys().next().value;
    if (oldest == null) break;
    dev.groups.delete(oldest);
  }
  group = { start, fired: false, count: 0, sum: {}, max: {}, min: {}, distinct: {} };
  dev.groups.set(key, group);
  return group;
}

/**
 * @param {any} group
 * @param {{ name: string, kind: string, field: string | null }[]} agg
 * @param {any} ev
 */
function applyAgg(group, agg, ev) {
  /** @type {Record<string, number>} */
  const values = {};
  let approximate = false;
  for (const item of agg) {
    if (item.kind === 'count') {
      group.count += 1;
      values[item.name] = group.count;
    } else if (item.kind === 'sum' || item.kind === 'max' || item.kind === 'min') {
      const sample = Number(ev[/** @type {string} */ (item.field)]);
      if (!Number.isFinite(sample)) continue;
      if (item.kind === 'sum') group.sum[item.name] = (group.sum[item.name] || 0) + sample;
      if (item.kind === 'max')
        group.max[item.name] = Math.max(group.max[item.name] ?? sample, sample);
      if (item.kind === 'min')
        group.min[item.name] = Math.min(group.min[item.name] ?? sample, sample);
      values[item.name] = group[item.kind][item.name];
    } else {
      const bucket = group.distinct[item.name] || { values: [], hll: null };
      pushDistinct(bucket, ev[/** @type {string} */ (item.field)]);
      group.distinct[item.name] = bucket;
      values[item.name] = bucket.hll ? count(fromJSON(bucket.hll)) : bucket.values.length;
      if (bucket.hll) approximate = true;
    }
  }
  if (approximate) values.approximate = 1;
  return values;
}

/**
 * @param {{ values: string[], hll: any }} bucket
 * @param {any} value
 */
function pushDistinct(bucket, value) {
  if (value == null) return;
  const text = String(value);
  if (!bucket.hll) {
    if (bucket.values.includes(text)) return;
    if (bucket.values.length < DISTINCT_EXACT) {
      bucket.values.push(text);
      return;
    }
    const sketch = createHll({ p: 10 });
    for (const item of bucket.values) add(sketch, item);
    add(sketch, text);
    bucket.values = [];
    bucket.hll = toJSON(sketch);
    return;
  }
  const sketch = fromJSON(bucket.hll);
  add(sketch, text);
  bucket.hll = toJSON(sketch);
}

/**
 * @param {{ name: string, op: string, value: number }[]} when
 * @param {Record<string, number>} values
 */
function whenHolds(when, values) {
  if (when.length === 0) return true;
  for (const row of when) {
    const got = values[row.name];
    if (typeof got !== 'number') return false;
    if (row.op === 'gt' && !(got > row.value)) return false;
    if (row.op === 'gte' && !(got >= row.value)) return false;
    if (row.op === 'lt' && !(got < row.value)) return false;
    if (row.op === 'lte' && !(got <= row.value)) return false;
    if (row.op === 'eq' && got !== row.value) return false;
  }
  return true;
}

/**
 * @param {any} spec
 * @param {any} ev
 * @param {any} ctx
 * @param {Record<string, number>} values
 */
function draft(spec, ev, ctx, values) {
  /** @type {Record<string, unknown>} */
  const data = { rule: spec.id };
  if (values.approximate) data.approximate = true;
  return {
    severity: ctx.options.severity,
    confidence: 0.8,
    ts: ev.ts,
    actual: spec.id,
    expected: 'rule did not match',
    explain: explainMatch({ observed: spec.id, matched: spec.id, source: 'rule' }),
    data,
  };
}

/**
 * @param {any} dev
 * @param {any} state
 */
function importRuleState(dev, state) {
  dev.groups = new Map();
  dev.partials = [];
  dev.learned = {};
  if (!state || typeof state !== 'object') return;
  if (state.groups != null) {
    if (!Array.isArray(state.groups) || state.groups.length > GROUP_CAP) {
      throw new HubvikError('ARRAY_GROUPS_EXCEEDS_CAP', 'array groups exceeds cap');
    }
    for (const pair of state.groups) {
      if (Array.isArray(pair) && pair.length === 2 && pair[1])
        dev.groups.set(String(pair[0]), pair[1]);
    }
  }
  if (state.partials != null) {
    if (!Array.isArray(state.partials) || state.partials.length > PARTIAL_CAP) {
      throw new HubvikError('ARRAY_PARTIALS_EXCEEDS_CAP', 'array partials exceeds cap');
    }
    dev.partials = state.partials.slice();
  }
  if (state.learned && typeof state.learned === 'object' && !Array.isArray(state.learned)) {
    dev.learned = state.learned;
  }
}

module.exports = { compileRules };
