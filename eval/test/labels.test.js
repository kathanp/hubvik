'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createEngine } = require('iotwarden');
const { main } = require('../cli.js');

test('eval --labels on the synthetic corpus prints precision with a Wilson interval', () => {
  const engine = createEngine({ learnMs: 1000, tiers: ['T0'] });
  /** @type {any[]} */
  const found = [];
  engine.on('anomaly', (item) => {
    if (item.detector === 'new-device') found.push(item);
  });
  engine.feed({ device: 'seed', dst: 'a.example', bytes: 1, ts: 0 });
  for (let i = 0; i < 20; i += 1) {
    engine.feed({ device: `d${i}`, dst: 'a.example', bytes: 1, ts: 5000 });
  }
  for (let i = 0; i < 20; i += 1) engine.feedback(found[i].id, i < 12 ? 'tp' : 'fp');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iotwarden-labels-'));
  const labels = path.join(dir, 'labels.jsonl');
  fs.writeFileSync(labels, engine.exportLabels());
  const corpus = path.join(__dirname, '..', 'fixtures', 'conn.log.labeled');
  /** @type {string[]} */
  const stdout = [];
  const original = console.log;
  console.log = (line) => stdout.push(String(line));
  try {
    main(['--dataset', 'iot23', '--zeek-logs', corpus, '--labels', labels], {
      outDir: dir,
      evasionPath: path.join(dir, 'evasion.md'),
    });
  } finally {
    console.log = original;
  }
  const line = stdout.find((item) => item.startsWith('precision:'));
  assert.ok(line, stdout.join('\n'));
  assert.match(line, /Wilson/);
  assert.match(line, /12\/20/);
});
