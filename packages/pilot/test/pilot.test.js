'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRunner, queueLabel, writeReport } = require('../src/index.js');

const LINE =
  'tcp 6 100 ESTABLISHED src=10.0.0.8 dst=1.2.3.4 sport=51515 dport=443 packets=10 bytes=1200 src=1.2.3.4 dst=10.0.0.8 sport=443 dport=51515 packets=8 bytes=9000\n';

test('a partial line is held until it is complete', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-pilot-'));
  const log = path.join(dir, 'conntrack.log');
  fs.writeFileSync(log, LINE.slice(0, 20));
  const runner = createRunner({ stateDir: path.join(dir, 'state'), conntrack: log });
  runner.step(1_000);
  assert.strictEqual(runner.engine.stats().events, 0);
  fs.appendFileSync(log, LINE.slice(20));
  runner.step(2_000);
  assert.ok(runner.engine.stats().events >= 1);
});

test('a shrunk log is read from the start', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-pilot-'));
  const log = path.join(dir, 'conntrack.log');
  fs.writeFileSync(log, LINE);
  const runner = createRunner({ stateDir: path.join(dir, 'state'), conntrack: log });
  runner.step(1_000);
  const first = runner.engine.stats().events;
  fs.truncateSync(log, 0);
  runner.step(1_500);
  fs.writeFileSync(log, LINE);
  runner.step(2_000);
  assert.ok(runner.engine.stats().events > first);
});

test('stop writes a checkpoint and a bad label is rejected', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-pilot-'));
  const state = path.join(dir, 'state');
  const runner = createRunner({ stateDir: state });
  queueLabel(state, { key: 'missing', verdict: 'nope' });
  runner.step(60_000);
  assert.ok(fs.existsSync(path.join(state, 'labels-rejected.jsonl')));
  runner.step(300_000);
  runner.stop(120_000);
  assert.ok(fs.readdirSync(state).some((name) => name.startsWith('checkpoint-')));
});

test('the weekly report prints n too small under 10 labels', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-pilot-'));
  const state = path.join(dir, 'state', 'events');
  fs.mkdirSync(state, { recursive: true });
  fs.writeFileSync(
    path.join(state, '2026-10-26.jsonl'),
    `${JSON.stringify({ detector: 'packet-flood', ts: Date.parse('2026-10-26T00:00:00Z') })}\n`,
  );
  fs.writeFileSync(
    path.join(dir, 'state', 'labels-applied.jsonl'),
    `${JSON.stringify({ detector: 'packet-flood', verdict: 'fp' })}\n`,
  );
  const out = path.join(dir, 'week.md');
  writeReport({
    stateDir: path.join(dir, 'state'),
    weekStart: Date.parse('2026-10-26T00:00:00Z'),
    weekEnd: Date.parse('2026-11-02T00:00:00Z'),
    out,
  });
  const text = fs.readFileSync(out, 'utf8');
  assert.match(text, /packet-flood: 1/);
  assert.match(text, /n too small/);
});
