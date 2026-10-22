'use strict';

const { HubvikError } = require('../errors');

const { createP2, push, quantile } = require('../engine/stats/p2');
const { createForest, push: pushPoint, score, refresh } = require('../engine/stats/hstree');
const { scratchBag } = require('./lib');
const { assertState } = require('./state');

const NAMES = [
  'bytesOut',
  'bytesIn',
  'flows',
  'destinations',
  'ports',
  'dns',
  'nxdomain',
  'failed',
];

/**
 * @returns {{ win: number | null, out: number, inn: number, flows: number, dst: Set<string>, ports: Set<number>, dns: number, nx: number, fail: number, attempts: number }}
 */
function blank() {
  return {
    win: null,
    out: 0,
    inn: 0,
    flows: 0,
    dst: new Set(),
    ports: new Set(),
    dns: 0,
    nx: 0,
    fail: 0,
    attempts: 0,
  };
}

/**
 * @param {any} ctx
 * @returns {string | null}
 */
function modelKey(ctx) {
  if (ctx.deviceClass && ctx.deviceClass.id) return `class:${ctx.deviceClass.id}`;
  if (ctx.peerGroup) return `peer:${ctx.peerGroup}`;
  return null;
}

/**
 * @param {any} feat
 * @param {number[]} max
 * @returns {number[]}
 */
function vector(feat, max) {
  const raw = [
    feat.out,
    feat.inn,
    feat.flows,
    feat.dst.size,
    feat.ports.size,
    feat.dns,
    feat.nx,
    feat.attempts > 0 ? feat.fail / feat.attempts : 0,
  ];
  return raw.map((value, index) => Math.log1p(value) / (max[index] > 0 ? max[index] : 1));
}

/**
 * @param {any} dev
 * @param {any} ev
 * @param {any} ctx
 */
function tally(dev, ev, ctx) {
  const start = ctx.window ? ctx.window.start : ev.ts;
  if (dev.feat.win !== start) {
    dev.feat = blank();
    dev.feat.win = start;
  }
  if (ev.type === 'flow') {
    dev.feat.out += ev.bytesOut || 0;
    dev.feat.inn += ev.bytesIn || 0;
    dev.feat.flows += 1;
    dev.feat.attempts += 1;
    if (ev.dst) dev.feat.dst.add(String(ev.dst));
    if (ev.dstPort != null) dev.feat.ports.add(ev.dstPort);
    if (ev.tcpOutcome === 'rejected' || ev.tcpOutcome === 'no-response') dev.feat.fail += 1;
  } else if (ev.type === 'dns') {
    dev.feat.dns += 1;
    if (ev.rcode === 'NXDOMAIN') dev.feat.nx += 1;
  } else if (ev.type === 'summary') {
    dev.feat.out += ev.bytes || 0;
  }
}

const detector = {
  id: 'multivariate-outlier',
  version: 1,
  meta: {
    rel: '1.1',
    mode: 'shadow',
    fpRisk: 'Medium. Shadow until evidence says otherwise',
    consumes: ['summary', 'flow', 'dns'],
  },
  requires: ['T0'],
  category: 'behavior',
  hardRule: false,
  defaults: { severity: 'medium' },

  createState() {
    return { feat: blank(), streak: 0 };
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  learn(dev, ev, ctx) {
    if (!ctx.outlier) return;
    tally(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    if (!ctx.outlier) return;
    tally(dev, ev, ctx);
  },

  /** @param {any} dev @param {any} win @param {any} ctx */
  onWindowClose(dev, win, ctx) {
    if (!ctx.outlier) return;
    const key = modelKey(ctx);
    if (!key) return;
    const raw = [
      dev.feat.out,
      dev.feat.inn,
      dev.feat.flows,
      dev.feat.dst.size,
      dev.feat.ports.size,
      dev.feat.dns,
      dev.feat.nx,
      dev.feat.attempts > 0 ? dev.feat.fail / dev.feat.attempts : 0,
    ];
    const empty = raw.every((value) => value === 0);
    const models = scratchBag(ctx, 'model:outlier', () => ({ rows: new Map() }));
    let model = models.rows.get(key);
    if (!model) {
      if (models.rows.size >= 16) return;
      model = { forest: createForest(7), p2: createP2(0.1), max: new Array(8).fill(0), seen: 0 };
      models.rows.set(key, model);
    }
    if (ctx.learning) {
      for (let i = 0; i < 8; i += 1) model.max[i] = Math.max(model.max[i], Math.log1p(raw[i]));
    }
    const point = vector(dev.feat, model.max);
    dev.feat = blank();
    if (empty) return;
    if (ctx.learning) {
      const value = pushPoint(model.forest, point);
      model.seen += 1;
      if (model.seen > 20) push(model.p2, value);
      if (model.seen % 250 === 0) refresh(model.forest);
      dev.streak = 0;
      return;
    }
    const value = score(model.forest, point);
    if (model.p2.count < 5 || value >= quantile(model.p2)) {
      dev.streak = 0;
      return;
    }
    dev.streak += 1;
    if (dev.streak < 3) return;
    const ranked = point
      .map((item, index) => ({ name: NAMES[index], item }))
      .sort((a, b) => a.item - b.item)
      .slice(0, 3)
      .map((item) => item.name);
    return {
      severity: ctx.options.severity,
      confidence: 0.7,
      ts: win.start,
      actual: `window score ${value}`,
      expected: `at or above the learned 0.1 percentile ${quantile(model.p2)}`,
      explain: { test: 'lt', observed: value, features: ranked },
      data: { score: value, features: ranked },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    return { streak: dev.streak };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.feat = blank();
    dev.streak = 0;
    if (state && Number.isInteger(state.streak)) {
      if (state.streak > 100)
        throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array streak exceeds cap');
      dev.streak = state.streak;
    }
  },

  memoryEstimate() {
    return 64;
  },
};

module.exports = detector;
