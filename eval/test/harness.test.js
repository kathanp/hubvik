'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { loadIot23 } = require('../iot23.js');
const { runEvasion } = require('../evasion/scenarios.js');
const { main } = require('../cli.js');
const {
  DAY,
  GRACE_MS,
  wilson,
  formatRate,
  planDevice,
  attackIntervals,
  aboveGate,
  inDetectionWindow,
  hitsFor,
  evaluate,
  renderMarkdown,
  summaryLines,
} = require('../protocol.js');

const FIXTURE = path.join(__dirname, 'fixtures');

test('wilson intervals match the hand-computed z=1.96 bounds', () => {
  assert.strictEqual(wilson(0, 20).low, 0);
  assert.strictEqual(wilson(20, 20).high, 1);
  const mid = wilson(10, 20);
  assert.ok(mid.low < 0.5 && mid.high > 0.5);
  assert.strictEqual(wilson(18, 20).low.toFixed(4), '0.6990');
  assert.strictEqual(wilson(18, 20).high.toFixed(4), '0.9721');
  assert.strictEqual(wilson(0, 25).low.toFixed(4), '0.0000');
  assert.strictEqual(wilson(0, 25).high.toFixed(4), '0.1332');
  assert.strictEqual(wilson(25, 25).low.toFixed(4), '0.8668');
  assert.strictEqual(wilson(25, 25).high.toFixed(4), '1.0000');
  assert.strictEqual(formatRate(0, 0, 'attack instances'), 'no rate');
  assert.strictEqual(
    formatRate(1, 3, 'attack instances'),
    'n too small (1 detected, 3 attack instances)',
  );
  const full = formatRate(20, 20, 'attack instances');
  assert.match(full, /20\/20 = 100\.0%/);
  assert.match(full, /95% Wilson/);
});

test('a benign prefix under 24 h is recorded, and 24 h is used when the capture has it', () => {
  const short = planDevice([
    { ts: 0, malicious: false },
    { ts: 60_000, malicious: true },
  ]);
  assert.strictEqual(short.learningMs, 60_000);
  assert.strictEqual(short.short, true);
  assert.strictEqual(short.learn.length, 1);
  assert.strictEqual(short.rest.length, 1);

  const long = planDevice([
    { ts: 0, malicious: false },
    { ts: DAY, malicious: false },
  ]);
  assert.strictEqual(long.learningMs, DAY);
  assert.strictEqual(long.short, false);
  assert.strictEqual(long.rest.length, 1);
});

test('attack instances merge when the gap is under 5 minutes', () => {
  const twoMin = attackIntervals('cam', [
    { ts: 0, malicious: true, label: 'Malicious', detailedLabel: 'C&C' },
    { ts: 2 * 60 * 1000, malicious: true, label: 'Malicious', detailedLabel: 'C&C' },
  ]);
  assert.strictEqual(twoMin.length, 1);
  assert.strictEqual(twoMin[0].flows, 2);
  const tenMin = attackIntervals('cam', [
    { ts: 0, malicious: true, label: 'Malicious', detailedLabel: 'C&C' },
    { ts: 10 * 60 * 1000, malicious: true, label: 'Malicious', detailedLabel: 'C&C' },
  ]);
  assert.strictEqual(tenMin.length, 2);
  const exact = attackIntervals('cam', [
    { ts: 0, malicious: true, label: 'Malicious', detailedLabel: 'C&C' },
    { ts: 5 * 60 * 1000, malicious: true, label: 'Malicious', detailedLabel: 'C&C' },
  ]);
  assert.strictEqual(exact.length, 2);

  const interval = { device: 'cam', start: 0, end: 1000 };
  const edge = { device: 'cam', ts: 1000 + GRACE_MS, severity: 'high', detector: 'x' };
  const late = { device: 'cam', ts: 1000 + GRACE_MS + 1, severity: 'high', detector: 'x' };
  const low = { device: 'cam', ts: 1000, severity: 'low', detector: 'x' };
  assert.strictEqual(inDetectionWindow(interval, edge), true);
  assert.strictEqual(inDetectionWindow(interval, late), false);
  assert.deepStrictEqual(
    hitsFor(interval, [edge, late, low]).map((item) => item.ts),
    [edge.ts],
  );
});

test('C6.3 proposals fire only above the per-day and per-week gates', () => {
  assert.strictEqual(aboveGate('medium', 1, 1), true);
  assert.strictEqual(aboveGate('medium', 1, 1.1), false);
  assert.strictEqual(aboveGate('high', 1, 7), true);
  assert.strictEqual(aboveGate('critical', 1, 8), false);
  assert.strictEqual(aboveGate('low', 100, 1), false);
  assert.strictEqual(aboveGate('medium', 1, 0), false);
});

test('IoT-23 conn.log.labeled joins through adapter-zeek on tier T1', () => {
  const rows = loadIot23(FIXTURE);
  assert.ok(rows.length > 20);
  assert.strictEqual(rows[0].event.type, 'flow');
  assert.strictEqual(rows[0].malicious, false);
  assert.ok(rows.some((row) => row.detailedLabel === 'PartOfAHorizontalPortScan'));
  const result = evaluate(rows, { tiers: ['T1'], dataset: 'iot23' });
  assert.strictEqual(result.tiers.length, 1);
  assert.strictEqual(result.tiers[0], 'T1');
  assert.strictEqual(result.attackInstances, 1);
  assert.strictEqual(result.detected, 1);
  assert.match(result.detection, /^n too small/);
  assert.ok(result.hits[0].detectors.includes('horizontal-scan'));
  assert.ok(result.learning[0].short);
  assert.match(renderMarkdown(result), /## Misses/);
  const scan = result.ablation.find((row) => row.detector === 'horizontal-scan');
  assert.strictEqual(scan.unique, 1);
  assert.strictEqual(scan.exercised, true);
  assert.strictEqual(scan.proposal, null);
  const dga = result.ablation.find((row) => row.detector === 'dga');
  assert.strictEqual(dga.exercised, false);
  assert.strictEqual(dga.zeroUnique, false);
  const md = renderMarkdown(result);
  assert.match(md, /## Not exercised/);
  assert.match(md, /- dga\n/);
  assert.doesNotMatch(md, /dga: 0 unique/);
});

test('the cli writes json and markdown and rejects an unknown dataset', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-eval-'));
  const result = main(['--dataset', 'iot23', '--zeek-logs', FIXTURE], {
    outDir: dir,
    evasionPath: path.join(dir, 'evasion.md'),
    quiet: true,
  });
  const json = JSON.parse(fs.readFileSync(path.join(dir, 'iot23.json'), 'utf8'));
  const md = fs.readFileSync(path.join(dir, 'iot23.md'), 'utf8');
  assert.strictEqual(json.detected, result.detected);
  assert.match(md, /n too small/);
  assert.match(md, /Thresholds were not tuned/);
  assert.strictEqual(json.evasion.length, 4);
  assert.throws(() => main(['--dataset', 'not-a-dataset', '--zeek-logs', FIXTURE]), /no joiner/);
  const bad = path.join(dir, 'conn.log.labeled');
  fs.writeFileSync(bad, '#separator \\x09\n#fields\tts\tuid\n1\tC\n');
  assert.throws(() => loadIot23(bad), /missing label/);
});

test('the synthetic corpus matches the committed golden report', () => {
  const corpus = path.join(__dirname, '..', 'fixtures', 'conn.log.labeled');
  const goldenMd = fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'golden.md'), 'utf8');
  const goldenJson = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'golden.json'), 'utf8'),
  );
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-corpus-'));
  const stdout = [];
  const original = console.log;
  console.log = (line) => stdout.push(String(line));
  let result;
  try {
    result = main(['--dataset', 'iot23', '--zeek-logs', corpus], {
      outDir: dir,
      evasionPath: path.join(dir, 'evasion.md'),
    });
  } finally {
    console.log = original;
  }
  assert.deepStrictEqual(stdout, summaryLines(result));
  assert.strictEqual(stdout.length, 7);
  assert.match(stdout[5], /^calibratedConfidence detection: /);
  assert.match(stdout[6], /^calibratedConfidence FP\/device-day: /);
  assert.strictEqual(fs.readFileSync(path.join(dir, 'iot23.md'), 'utf8'), goldenMd);
  assert.strictEqual(
    fs.readFileSync(path.join(dir, 'iot23.proposals.md'), 'utf8'),
    fs.readFileSync(path.join(__dirname, '..', 'fixtures', 'golden.proposals.md'), 'utf8'),
  );
  assert.deepStrictEqual(
    JSON.parse(fs.readFileSync(path.join(dir, 'iot23.json'), 'utf8')),
    goldenJson,
  );
  assert.strictEqual(
    fs.readFileSync(path.join(dir, 'evasion.md'), 'utf8'),
    fs.readFileSync(path.join(__dirname, '..', 'results', 'evasion.md'), 'utf8'),
  );
  assert.match(result.detection, /% \(95% Wilson/);
  assert.match(result.strictDetection, /% \(95% Wilson/);
  const udp = result.byLabel.find((row) => row.detailedLabel === 'UdpFlood');
  assert.match(udp.strict, /95% Wilson/);
  const scanType = result.byLabel.find((row) => row.detailedLabel === 'HorizontalScan');
  assert.match(scanType.strict, /95% Wilson/);
  assert.match(goldenMd, /Strict detection:/);
  assert.match(goldenMd, /UdpFlood:.*strict /);
  assert.match(goldenMd, /n too small/);
  assert.match(goldenMd, /time to detect/);
  assert.match(goldenMd, /per benign device-day/);
  assert.match(goldenMd, /## Ablation/);
  assert.ok(result.attackInstances >= 20);
  assert.strictEqual(result.benignDeviceDays, 3);
  assert.ok(result.learning.every((row) => row.learningMs === 2 * 24 * 60 * 60 * 1000));
  assert.strictEqual(result.poisonedPrefix, false);
  assert.strictEqual(result.maliciousLearnShare, 0);
  assert.match(goldenMd, /Learning span: 172800000 ms/);
  assert.match(goldenMd, /Malicious-label share inside the learning prefix: 0\//);
  assert.doesNotMatch(goldenMd, /POISONED PREFIX/);
});

test('a learning prefix that contains a malicious label is marked poisoned', () => {
  const md = renderMarkdown({
    dataset: 'iot23',
    tiers: ['T1'],
    learning: [{ device: 'cam', learningMs: 1000, short: true }],
    learnEvents: 4,
    maliciousLearnEvents: 1,
    maliciousLearnShare: 0.25,
    poisonedPrefix: true,
    detection: 'no rate',
    falsePositives: 0,
    benignDeviceDays: 0,
    falsePositivesPerDeviceDay: null,
    benignIntervalsWithFalsePositive: 'no rate',
    byLabel: [],
    hits: [],
    misses: [],
    ablation: [],
    proposals: [],
  });
  assert.match(md, /Learning span: 1000 ms/);
  assert.match(md, /Malicious-label share inside the learning prefix: 1\/4/);
  assert.match(md, /POISONED PREFIX/);
});

test('the markdown report covers the other section branches', () => {
  const md = renderMarkdown({
    dataset: 'ciciot2023',
    tiers: ['T1', 'T2'],
    learning: [
      { device: 'cam', learningMs: 1000, short: true },
      { device: 'plug', learningMs: 2000, short: false },
    ],
    learnEvents: 0,
    maliciousLearnEvents: 0,
    maliciousLearnShare: 0,
    poisonedPrefix: false,
    detection: 'n too small',
    strictDetection: 'n too small',
    falsePositives: 2,
    benignDeviceDays: 1,
    falsePositivesPerDeviceDay: 2,
    excludedEvents: 3,
    benignIntervalsWithFalsePositive: 'no rate',
    calibrated: {
      detection: 'n too small',
      falsePositives: 0,
      benignDeviceDays: 0,
      falsePositivesPerDeviceDay: null,
    },
    byLabel: [
      { detailedLabel: 'Flood', detection: 'n too small', strict: null },
      { detailedLabel: 'Scan', detection: '1/1', strict: '1/1' },
    ],
    hits: [
      {
        device: 'cam',
        detailedLabel: 'Flood',
        start: 1,
        end: 2,
        timeToDetectMs: 5,
        detectors: ['a'],
      },
    ],
    misses: [{ device: 'plug', detailedLabel: 'Scan', start: 3, end: 4, flows: 2 }],
    ablation: [
      { detector: 'quiet', exercised: true, unique: 0, falsePositives: 4, zeroUnique: true },
      { detector: 'loud', exercised: true, unique: 1, falsePositives: 0, zeroUnique: false },
      { detector: 'idle', exercised: false },
    ],
    proposals: ['leave bogon-destination at its default'],
    evasion: [
      { id: 'slow-scan', detectors: ['slow-scan'], fired: true },
      { id: 'split-flood', detectors: [], fired: false },
    ],
  });
  assert.match(md, /UNVERIFIED/);
  assert.match(md, /Excluded labels: 3 events/);
  assert.match(md, /calibratedConfidence detection/);
  assert.match(md, /no rate \(0 device-days\)/);
  assert.match(md, /2 per benign device-day/);
  assert.match(md, /Flood: n too small/);
  assert.match(md, /Scan: 1\/1; strict 1\/1/);
  assert.match(md, /time to detect 5 ms/);
  assert.match(md, /quiet: 0 unique detections, 4 false positives, zero unique/);
  assert.match(md, /- idle/);
  assert.match(md, /leave bogon-destination/);
  assert.match(md, /slow-scan: fired \(slow-scan\)/);
  assert.match(md, /split-flood: no medium-or-above anomaly \(none\)/);
  assert.match(md, /cam 1000 ms; plug 2000 ms/);
});

test('fp-breakdown writes counts and keeps proposals off the result files', () => {
  const corpus = path.join(__dirname, '..', 'fixtures', 'conn.log.labeled');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hubvik-fp-'));
  /** @type {string[]} */
  const stdout = [];
  const original = console.log;
  console.log = (line) => stdout.push(String(line));
  try {
    main(['--dataset', 'iot23', '--zeek-logs', corpus, '--fp-breakdown'], {
      outDir: dir,
      evasionPath: path.join(dir, 'evasion.md'),
    });
  } finally {
    console.log = original;
  }
  const json = JSON.parse(fs.readFileSync(path.join(dir, 'iot23', 'fp-breakdown.json'), 'utf8'));
  assert.strictEqual(typeof json.falsePositives, 'number');
  assert.ok(json.byDetector && json.byClass && json.byHour && json.topActual);
  assert.strictEqual(Object.hasOwn(json, 'proposals'), false);
  const md = fs.readFileSync(path.join(dir, 'iot23', 'fp-breakdown.md'), 'utf8');
  assert.match(md, /By detector/);
  assert.match(md, /By UTC hour/);
  assert.doesNotMatch(md, /proposal:/);
  for (const line of stdout) {
    if (line.startsWith('proposal:')) assert.match(line, /move to info/);
  }
});

test('the evasion suite builds the four C6.2 shapes and records what fired', () => {
  const scenarios = runEvasion();
  assert.deepStrictEqual(
    scenarios.map((item) => item.id),
    ['slow-scan', 'beacon-jitter-40', 'exfil-0.9-limit', 'flood-10-destinations'],
  );
  for (const scenario of scenarios) {
    assert.strictEqual(typeof scenario.fired, 'boolean');
    assert.ok(Array.isArray(scenario.detectors));
  }
});
