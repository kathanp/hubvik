'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { advance, compile, createBook } = require('../../src/engine/templates');

const DIR = path.join(__dirname, '..', '..', '..', '..', 'examples', 'templates');
const FILES = [
  'mirai-loader.json',
  'kimwolf-pivot.json',
  'dns-c2.json',
  'ot-sabotage.json',
  'staged-exfil.json',
];

const known = new Set([
  'exploit-probe-http',
  'exploit-then-download',
  'horizontal-scan',
  'proxy-sdk-traffic',
  'lan-via-proxy',
  'adb-exposure',
  'dga',
  'new-beacon',
  'ot-recon',
  'ot-write-new',
  'ot-dangerous-op',
  'long-connection',
  'slow-exfil',
  'cloud-storage-exfil',
  'new-destination',
]);

test('each example template matches its own step replay', () => {
  for (const file of FILES) {
    const raw = JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8'));
    const book = createBook();
    book.templates = compile([raw], known);
    const hits = [];
    raw.steps.forEach((step, index) => {
      const detector = step.detector || step.any[0];
      hits.push(
        ...advance(book, {
          detector,
          device: 'cam',
          ts: 1000 * (index + 1),
          id: `a${index}`,
          severity: 'high',
        }),
      );
    });
    assert.strictEqual(hits.length, 1, file);
    assert.strictEqual(hits[0].templateId, raw.id);
  }
});

test('a benign detector sequence matches no example', () => {
  const list = FILES.map((file) => JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8')));
  const book = createBook();
  book.templates = compile(list, known);
  const hits = [];
  for (let i = 0; i < 5; i += 1) {
    hits.push(
      ...advance(book, {
        detector: 'new-destination',
        device: 'cam',
        ts: 1000 * (i + 1),
        id: `b${i}`,
        severity: 'low',
      }),
    );
  }
  assert.deepStrictEqual(hits, []);
});

test('compile rejects malformed templates', () => {
  const bad = [
    null,
    [{ id: 'a', steps: [{ detector: 'nope' }], within: '1h', by: 'device' }],
    [{ id: 'a', steps: [], within: '1h', by: 'device' }],
    [{ id: '', steps: [{ detector: 'new-destination' }], within: '1h', by: 'device' }],
    [{ id: 'a', steps: [{ detector: 'new-destination' }], within: '9d', by: 'device' }],
    [{ id: 'a', steps: [{ detector: 'new-destination' }], within: '1h', by: 'nope' }],
    [
      {
        id: 'a',
        steps: [{ detector: 'new-destination' }],
        within: '1h',
        by: 'device',
        llrBonus: 9,
      },
    ],
    [{ id: 'a', steps: [null], within: '1h', by: 'device' }],
  ];
  for (const list of bad) {
    assert.throws(
      () => compile(list, known),
      (err) => err.code === 'TEMPLATE_INVALID',
    );
  }
  assert.throws(
    () => compile('nope', known),
    (err) => err.code === 'TEMPLATE_INVALID',
  );
});
