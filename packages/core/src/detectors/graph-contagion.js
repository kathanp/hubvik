'use strict';

const { HubvikError } = require('../errors');

const { createHawkes, excited, observe } = require('../engine/stats/hawkes');
const { assertState } = require('./state');

const STAGES_CAP = 8;
const MIN_NEIGHBORS = 2;

const detector = {
  id: 'graph-contagion',
  version: 1,
  meta: {
    rel: '1.2',
    mode: 'shadow',
    fpRisk: 'Medium when the graph is dense. No graph means no alert',
    consumes: [],
    attack: ['T1021'],
  },
  requires: ['T1'],
  category: 'fleet',
  hardRule: false,
  defaults: { severity: 'high' },

  createState() {
    return { stages: new Map() };
  },

  /**
   * @param {any} dev
   * @param {string} stage
   * @param {number} ts
   * @param {{ severity: string }} options
   */
  observe(dev, stage, ts, options) {
    let row = dev.stages.get(stage);
    if (!row) {
      if (dev.stages.size >= STAGES_CAP) {
        const oldest = dev.stages.keys().next().value;
        if (oldest != null) dev.stages.delete(oldest);
      }
      row = { hawkes: createHawkes(), fired: false };
      dev.stages.set(stage, row);
    }
    if (row.fired) return;
    observe(row.hawkes, ts);
    if (row.hawkes.times.length < MIN_NEIGHBORS || !excited(row.hawkes, ts)) return;
    row.fired = true;
    return {
      severity: options.severity,
      confidence: 0.8,
      ts,
      actual: stage,
      expected: 'a stage that is not spreading across LAN neighbors',
      data: { stage, neighbors: row.hawkes.times.length },
    };
  },

  /** @param {any} dev */
  exportState(dev) {
    /** @type {any[]} */
    const stages = [];
    for (const [stage, row] of dev.stages) {
      stages.push([stage, { times: row.hawkes.times.slice(), fired: row.fired }]);
    }
    return { stages };
  },

  /** @param {any} dev @param {any} state */
  importState(dev, state) {
    assertState(state, detector.id);
    dev.stages = new Map();
    if (!state || !Array.isArray(state.stages)) return;
    if (state.stages.length > STAGES_CAP)
      throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array stages exceeds cap');
    for (const entry of state.stages) {
      if (!Array.isArray(entry)) continue;
      const raw = entry[1] || {};
      const hawkes = createHawkes();
      if (Array.isArray(raw.times)) {
        if (raw.times.length > 32)
          throw new HubvikError('ARRAY_EXCEEDS_CAP', 'array times exceeds cap');
        for (const time of raw.times) hawkes.times.push(Number(time));
      }
      dev.stages.set(String(entry[0]), { hawkes, fired: Boolean(raw.fired) });
    }
  },

  memoryEstimate() {
    return 512;
  },
};

module.exports = detector;
