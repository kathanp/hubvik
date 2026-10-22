'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { createEngine } = require('../../src/index.js');
const { simulate } = require('../../../../test/fixtures/sim');
const { CLASS_NAMES } = require('../../../../test/fixtures/profiles');
const { T0, DAY, H } = require('../../../../test/fixtures/clock');

const TIERS = ['T0', 'T1', 'T2', 'T3', 'T4', 'T5'];
const TEMPLATES = path.join(__dirname, '..', '..', '..', '..', 'examples', 'templates');

/**
 * @param {any[]} events
 * @param {Record<string, unknown>} opts
 * @param {(engine: any, events: any[]) => void} [prepare]
 * @returns {{ anomalies: any[], warnings: any[], matches: any[] }}
 */
function replay(events, opts, prepare) {
  const engine = createEngine({
    learnMs: 7 * DAY,
    tiers: TIERS,
    identity: 'auto',
    ...opts,
  });
  const anomalies = [];
  const warnings = [];
  const matches = [];
  engine.on('anomaly', (row) => anomalies.push(row));
  engine.on('warning', (row) => warnings.push(row));
  engine.on('template-match', (row) => matches.push(row));
  if (prepare) prepare(engine, events);
  const device = events[0] && events[0].device;
  if (device) engine.setDeviceClass(device, events.profile || 'camera');
  for (const event of events) engine.feed(event);
  engine.flush(events[events.length - 1].ts + 60_000);
  return { anomalies, warnings, matches };
}

/**
 * @param {any} row
 * @returns {string}
 */
function fingerprint(row) {
  return `${row.detector}|${row.ts}|${row.severity}|${row.fingerprint}`;
}

test('benign matrices match with and without annotations', () => {
  const templates = fs
    .readdirSync(TEMPLATES)
    .filter((name) => name.endsWith('.json'))
    .map((name) => JSON.parse(fs.readFileSync(path.join(TEMPLATES, name), 'utf8')));
  for (const seed of [1, 2, 3]) {
    for (const profile of CLASS_NAMES) {
      for (const rich of [false, true]) {
        const events = simulate({
          profile,
          days: 14,
          seed,
          startTs: T0,
          rich,
          discovery: true,
          ipv6: true,
        });
        events.profile = profile;
        const plain = replay(events, {});
        const noted = replay(events, {}, (engine) => {
          if (rich && events.firmwareUpdate) {
            const window = events.firmwareUpdate;
            engine.annotate(window.target, {
              kind: window.kind,
              fromTs: window.fromTs,
              untilTs: window.untilTs,
              note: window.note,
            });
          } else {
            engine.annotate(events[0].device, {
              kind: 'maintenance',
              fromTs: T0 + 3 * DAY,
              untilTs: T0 + 3 * DAY + 6 * H,
              note: 'matrix window',
            });
          }
        });
        assert.deepStrictEqual(
          noted.anomalies.map(fingerprint).sort(),
          plain.anomalies.map(fingerprint).sort(),
          `${profile} seed ${seed} rich ${rich}`,
        );
        if (rich && events.firmwareUpdate) {
          const window = events.firmwareUpdate;
          for (const row of noted.anomalies) {
            if (!row.context) continue;
            if (row.ts < window.fromTs || row.ts >= window.untilTs) continue;
            assert.strictEqual(row.incidentId, undefined, row.detector);
          }
        }
      }
      const events = simulate({
        profile,
        days: 14,
        seed,
        startTs: T0,
        rich: true,
        discovery: true,
        ipv6: true,
      });
      events.profile = profile;
      const drift = replay(events, { drift: true });
      const perDevice = new Map();
      for (const row of drift.warnings) {
        if (row.code !== 'BASELINE_DRIFT') continue;
        perDevice.set(row.device, (perDevice.get(row.device) || 0) + 1);
      }
      for (const [device, count] of perDevice) {
        assert.ok(count <= 1, `${device} ${profile} seed ${seed} emitted ${count}`);
      }
      const chained = replay(events, { alerts: true }, (engine) => {
        engine.loadTemplates(templates);
      });
      assert.deepStrictEqual(chained.matches, [], `${profile} seed ${seed}`);
    }
  }
});

test('peer clusters on simulator seeds 1–3 stay class-pure', () => {
  for (const seed of [1, 2, 3]) {
    const engine = createEngine({
      peerSuggest: true,
      learnMs: 3 * DAY,
      tiers: TIERS,
    });
    /** @type {Map<string, string>} */
    const classes = new Map();
    for (const profile of CLASS_NAMES) {
      const events = simulate({
        profile,
        days: 2,
        seed,
        startTs: T0,
        rich: false,
      });
      for (let copy = 0; copy < 3; copy += 1) {
        const id = `${profile}-${seed}-${copy}`;
        classes.set(id, profile);
        for (const event of events) {
          engine.feed({ ...event, device: id });
        }
      }
    }
    engine.lock();
    const suggestions = engine.stats().peerSuggestions;
    for (const group of suggestions) {
      const counts = new Map();
      for (const id of group.devices) {
        const name = classes.get(id);
        counts.set(name, (counts.get(name) || 0) + 1);
      }
      assert.strictEqual(counts.size, 1, JSON.stringify(group.devices));
      const size = group.devices.length;
      const top = Math.max(...counts.values());
      assert.ok(top / size >= 0.9, `${top}/${size}`);
    }
  }
});
