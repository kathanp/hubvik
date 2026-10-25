'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../core');
const { createParser } = require('../src/index.js');

/**
 * @param {number} ts
 * @param {number} port
 * @param {string} state
 */
function line(ts, port, state) {
  const reply =
    state === 'ESTABLISHED'
      ? ` src=10.0.0.8 dst=8.8.8.8 sport=${port} dport=9 packets=4 bytes=200`
      : ' [UNREPLIED]';
  return `tcp 6 60 ${state} src=8.8.8.8 dst=10.0.0.8 sport=9 dport=${port} packets=1 bytes=40${reply}`;
}

test('a conntrack list drives port-knock', () => {
  let ts = 1_000_000;
  const parser = createParser({ now: () => ts });
  const eng = createEngine({
    learnMs: 0,
    windowMs: 60000,
    tiers: ['T1'],
    shadow: ['port-knock'],
  });
  /** @type {string[]} */
  const ids = [];
  eng.on('shadow-anomaly', (row) => ids.push(row.detector));
  for (const row of [
    line(0, 1111, 'SYN_SENT'),
    line(0, 2222, 'SYN_SENT'),
    line(0, 3333, 'SYN_SENT'),
    line(0, 4444, 'ESTABLISHED'),
  ]) {
    ts += 1000;
    for (const event of parser.write(row)) eng.feed(event);
  }
  assert.ok(ids.includes('port-knock'));
});
