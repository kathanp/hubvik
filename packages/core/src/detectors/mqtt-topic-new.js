'use strict';

const { seenState, exportSeen, importSeen, memorySeen } = require('./lib');

const detector = {
  id: 'mqtt-topic-new',
  version: 1,
  meta: {
    consumes: ['app'],
    rel: '0.4',
    fpRisk: '',
  },
  requires: ['T5'],
  category: 'app',
  defaults: { severity: 'medium' },

  /** @param {any} caps */
  createState(caps) {
    return seenState(caps);
  },

  /** @param {any} dev @param {any} ev */
  learn(dev, ev) {
    const topic = topicOf(ev);
    if (topic) dev.seen.add(topic);
  },

  /** @param {any} dev @param {any} ev @param {any} ctx */
  check(dev, ev, ctx) {
    const topic = topicOf(ev);
    if (!topic || dev.seen.has(topic) || dev.fired.has(topic)) return;
    dev.fired.add(topic);
    return {
      severity: ctx.options.severity,
      confidence:
        topic.includes('cmd') || topic.includes('ota') || topic.includes('config') ? 0.85 : 0.7,
      ts: ev.ts,
      actual: topic,
      expected: 'only a learned topic prefix',
      data: { topic },
    };
  },

  exportState: exportSeen,
  /** @param {any} dev @param {any} state @param {any} caps */
  importState(dev, state, caps) {
    importSeen(dev, state, caps, detector.id);
  },
  memoryEstimate: memorySeen,
};

/**
 * @param {any} ev
 */
function topicOf(ev) {
  if (ev.type !== 'app' || ev.proto !== 'mqtt' || !ev.target) return null;
  if (ev.op !== 'PUBLISH' && ev.op !== 'SUBSCRIBE') return null;
  return ev.target.split('/').slice(0, 2).join('/');
}

module.exports = detector;
