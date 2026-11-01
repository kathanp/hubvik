'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');
const { noteIncident } = require('../src/engine/incidents');
const { allowFamilyAlert, FAMILY_CAP } = require('../src/engine/families');
const { fanout } = require('../../../test/fixtures/attacks');

test('families defaults to off and rejects any other value', () => {
  assert.strictEqual(createEngine().opts.families, false);
  assert.throws(
    () => createEngine({ families: 'scan' }),
    (err) => err.code === 'FAMILIES_IS_INVALID',
  );
});

test('families true marks a scan anomaly and false leaves it unmarked', () => {
  const marked = fireFanout({ families: true });
  const plain = fireFanout({});
  assert.strictEqual(marked.data.family, 'scan');
  assert.strictEqual(plain.data.family, undefined);
});

test('one family keeps the heavier incident weight', () => {
  const incidents = [];
  const engine = {
    opts: { incidentWindowMs: 3_600_000, scoring: 'additive' },
    incidentSeq: 0,
    emit(_name, body) {
      incidents.push(body);
    },
  };
  const device = {};
  noteIncident(engine, device, anomaly('a1', 'high', 1000));
  noteIncident(engine, device, anomaly('a2', 'low', 1000));
  assert.strictEqual(incidents[1].score, incidents[0].score);
  assert.strictEqual(device.incident.anomalyIds.length, 2);
});

test('a lighter family alert in the same window is dropped and a hard rule is not', () => {
  const state = {};
  const heavy = anomaly('a1', 'high', 1000);
  const light = anomaly('a2', 'low', 1000);
  const hard = anomaly('a3', 'low', 1000);
  hard._partgHard = true;
  assert.strictEqual(allowFamilyAlert(state, heavy, 60_000), true);
  assert.strictEqual(allowFamilyAlert(state, light, 60_000), false);
  assert.strictEqual(allowFamilyAlert(state, hard, 60_000), true);
  assert.strictEqual(state.family.size, 1);
});

test('the family alert book stops at the family count', () => {
  const state = {};
  for (let i = 0; i < FAMILY_CAP; i++) {
    assert.strictEqual(allowFamilyAlert(state, named(`f${i}`), 60_000), true);
  }
  assert.strictEqual(allowFamilyAlert(state, named('overflow'), 60_000), false);
  assert.strictEqual(state.family.size, FAMILY_CAP);
});

/**
 * @param {object} opts
 */
function fireFanout(opts) {
  const engine = createEngine({ learnMs: 60_000, windowMs: 60_000, minFanout: 10, ...opts });
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.flush(60_000);
  const copy = createEngine({ learnMs: 60_000, windowMs: 60_000, minFanout: 10, ...opts });
  const alerts = [];
  copy.on('anomaly', (item) => {
    if (item.detector === 'fan-out') alerts.push(item);
  });
  copy.importBaseline(engine.exportBaseline({ createdAt: 1 }));
  for (const event of fanout('d', 120_000, 12)) copy.feed(event);
  assert.strictEqual(alerts.length, 1);
  return alerts[0];
}

/**
 * @param {string} id
 * @param {string} severity
 * @param {number} ts
 */
function anomaly(id, severity, ts) {
  return {
    id,
    detector: 'fan-out',
    device: 'd',
    severity,
    confidence: 1,
    ts,
    actual: 'hosts',
    data: { family: 'scan' },
  };
}

/**
 * @param {string} family
 */
function named(family) {
  const row = anomaly(family, 'high', 1000);
  row.data = { family };
  return row;
}
