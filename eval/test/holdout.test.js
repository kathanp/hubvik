'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  SEED,
  PAIRS_PER_HOUR,
  SCAN_HOURS,
  GAP_MS,
  JITTER,
  BEACON_MS,
  EXFIL_HOURS,
  exfilBytesPerHour,
  scenarios,
} = require('../evasion-holdout/scenarios.js');

test('holdout parameters differ from the published evasion suite', () => {
  assert.strictEqual(SEED, 20261018);
  assert.notStrictEqual(SEED, 20261017);
  const [scan, beacon, exfil] = scenarios();
  const attack = scan.events.slice(scan.learnCount);
  assert.strictEqual(attack.length, PAIRS_PER_HOUR * SCAN_HOURS);
  const ports = new Set(attack.map((event) => event.dstPort));
  assert.deepStrictEqual([...ports].sort(), [8080, 9443]);
  assert.ok(attack.every((event) => event.dstIp.startsWith('47.8.3.')));
  assert.ok(attack.every((event) => !event.dstIp.startsWith('45.2.1.')));

  const gaps = [];
  const beats = beacon.events.slice(beacon.learnCount);
  for (let i = 1; i < beats.length; i += 1) gaps.push(beats[i].ts - beats[i - 1].ts);
  assert.ok(beats.length >= 30);
  assert.ok(beats[beats.length - 1].ts - beats[0].ts <= BEACON_MS);
  assert.ok(gaps.every((gap) => gap >= GAP_MS * (1 - JITTER) && gap <= GAP_MS * (1 + JITTER)));
  assert.ok(gaps.some((gap) => gap !== GAP_MS));

  const uploads = exfil.events.slice(exfil.learnCount);
  assert.strictEqual(uploads.length, EXFIL_HOURS);
  assert.strictEqual(uploads[0].bytesOut, exfilBytesPerHour());
  assert.ok(uploads[0].bytesOut < 900_000);
});
