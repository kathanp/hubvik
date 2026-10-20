'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { createEngine } = require('hubvik');
const { checkRule, replay, doctor, reportHtml } = require('../src/lib.js');

test('rules check rejects a regex operator and replay uses the injected engine', () => {
  assert.ok(checkRule({ id: 'bad', on: 'flow', where: { dstPort: { regex: '23' } } }).length > 0);
  assert.deepStrictEqual(checkRule({ id: 'ok', on: 'flow', where: { dstPort: { eq: 23 } } }), []);
  const rows = replay('{"device":"d","dst":"a.example","bytes":10,"ts":1000}\n', {
    createEngine() {
      return {
        on(name, fn) {
          this.listeners[name] = fn;
        },
        listeners: {},
        feed() {
          this.listeners.anomaly({ detector: 'new-destination', ts: 1000 });
        },
        flush() {},
      };
    },
  });
  assert.strictEqual(rows[0].detector, 'new-destination');
  const html = reportHtml(
    '{"ts":1000,"device":"cam","detector":"fan-out","explain":"too many hosts"}\n{"ts":2000,"kind":"incident","device":"cam","stages":["recon"]}\n',
  );
  assert.strictEqual(
    html,
    '<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:sans-serif}</style></head><body><h1>Timeline</h1><section><h2>cam</h2><ol><li>1000 fan-out<p>too many hosts</p></li><li>2000 incident</li></ol></section><h1>Incidents</h1><ul><li>cam 2000</li></ul><h1>Detectors</h1><ol><li>fan-out 1</li></ol></body></html>',
  );
  assert.doesNotMatch(html, /src=/);
});

test('doctor counts clock disorder and inactive detectors', () => {
  const report = doctor(
    '{"device":"d","dst":"a.example","bytes":10,"ts":9000}\n{"device":"d","dst":"b.example","bytes":10,"ts":1000}\nnot-json\n',
    {
      tiers: ['T0'],
      createEngine() {
        return {
          on() {},
          feed() {},
          stats() {
            return {
              detectors: { 'fan-out': { active: false, reason: 'disabled by configuration' } },
            };
          },
        };
      },
    },
  );
  assert.strictEqual(report.clockDisorder, 1);
  assert.strictEqual(report.reorderMs5000WouldAbsorb, 0);
  assert.strictEqual(report.malformed, 1);
  assert.deepStrictEqual(report.inactive, [{ id: 'fan-out', reason: 'disabled by configuration' }]);
});

test('replay locks once the learn window has passed', () => {
  /** @type {string[]} */
  const calls = [];
  replay(
    '{"device":"d","dst":"a.example","bytes":10,"ts":1000}\n{"device":"d","dst":"b.example","bytes":10,"ts":5000}\n',
    {
      learnMs: 1000,
      lock: true,
      createEngine() {
        return {
          on() {},
          lock() {
            calls.push('lock');
          },
          feed() {
            calls.push('feed');
          },
          flush() {},
        };
      },
    },
  );
  assert.deepStrictEqual(calls, ['feed', 'lock', 'feed']);
});

test('the Kimwolf pivot replay report matches its HTML snapshot', () => {
  const events = fs.readFileSync(path.join(__dirname, 'kimwolf.jsonl'), 'utf8');
  const rows = replay(events, {
    createEngine,
    tiers: ['T0', 'T1', 'T2'],
    learnMs: 0,
    lock: true,
  });
  const html = reportHtml(rows.map((row) => JSON.stringify(row)).join('\n'));
  const snapshot = fs.readFileSync(path.join(__dirname, 'kimwolf.snapshot.html'), 'utf8');
  assert.strictEqual(html, snapshot);
  assert.doesNotMatch(html, /<script/);
  assert.match(html, /adb-exposure/);
  assert.match(html, /blockchain-c2/);
});
