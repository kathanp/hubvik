'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { HubvikError } = require('../../src/errors');
const {
  createAnnotationBook,
  add,
  remove,
  list,
  covers,
  abuse,
  endedFirmware,
  markSuggested,
  toJSON,
  fromJSON,
} = require('../../src/engine/annotations');

const DAY = 24 * 3600e3;
const WM = 30 * DAY;
const NEVER = [
  'threat-intel-match',
  'ot-dangerous-op',
  'ot-value-out-of-range',
  'onvif-config-change',
  'proxy-sdk-traffic',
  'suppression-abuse',
];

/**
 * @param {string} kind
 * @param {number} fromTs
 * @param {number} untilTs
 * @returns {{ kind: string, fromTs: number, untilTs: number }}
 */
function spec(kind, fromTs, untilTs) {
  return { kind, fromTs, untilTs };
}

/**
 * @param {ReturnType<typeof createAnnotationBook>} book
 * @param {() => void} fn
 */
function rejects(book, fn) {
  const before = structuredClone(toJSON(book));
  assert.throws(fn, (err) => {
    assert.ok(err instanceof HubvikError);
    assert.strictEqual(err.code, 'ANNOTATION_INVALID');
    return true;
  });
  assert.deepStrictEqual(toJSON(book), before);
}

test('64 active annotations per device, and the next one does not mutate', () => {
  const book = createAnnotationBook();
  for (let i = 0; i < 64; i++) add(book, 'cam', spec('maintenance', WM, WM + 1000), WM);
  assert.strictEqual(list(book, { device: 'cam' }).length, 64);
  const lock = add(book, 'lock', spec('maintenance', WM, WM + 1000), WM);
  assert.strictEqual(list(book, { device: 'lock' }).length, 1);
  rejects(book, () => add(book, 'cam', spec('maintenance', WM, WM + 1000), WM));
  assert.strictEqual(list(book, { device: 'cam' }).length, 64);
  assert.strictEqual(
    list(book, {}).some((row) => row.id === lock),
    true,
  );
});

test('256 active annotations for *', () => {
  const book = createAnnotationBook();
  for (let i = 0; i < 256; i++) add(book, '*', spec('network-change', WM, WM + 1000), WM);
  assert.strictEqual(list(book, { device: '*' }).length, 256);
  const cam = add(book, 'cam', spec('maintenance', WM, WM + 1000), WM);
  rejects(book, () => add(book, '*', spec('network-change', WM, WM + 1000), WM));
  assert.strictEqual(list(book, { device: '*' }).length, 256);
  assert.strictEqual(
    list(book, {}).some((row) => row.id === cam),
    true,
  );
});

test('device duration cap is 72h and * duration cap is 6h', () => {
  const deviceMax = 72 * 3600e3;
  const starMax = 6 * 3600e3;
  const book = createAnnotationBook();
  add(book, 'cam', spec('user-action', WM, WM + deviceMax), WM);
  rejects(book, () => add(book, 'cam', spec('user-action', WM, WM + deviceMax + 1), WM));
  add(book, '*', spec('network-change', WM, WM + starMax), WM);
  rejects(book, () => add(book, '*', spec('network-change', WM, WM + starMax + 1), WM));
  rejects(book, () => add(book, '*', spec('network-change', WM, WM + deviceMax), WM));
  assert.strictEqual(list(book, {}).length, 2);
});

test('fromTs may be at most 24h before the watermark', () => {
  const book = createAnnotationBook();
  const lead = 24 * 3600e3;
  add(book, 'cam', spec('maintenance', WM - lead, WM - lead + 1000), WM);
  rejects(book, () => add(book, 'cam', spec('maintenance', WM - lead - 1, WM - lead + 1000), WM));
  assert.strictEqual(list(book, {}).length, 1);
});

test('bad fields do not mutate the book', () => {
  const book = createAnnotationBook();
  const note = 'n'.repeat(255);
  add(
    book,
    'cam',
    { kind: 'maintenance', fromTs: WM, untilTs: WM + 1000, note, operator: 'ada' },
    WM,
  );
  rejects(book, () =>
    add(
      book,
      'cam',
      { kind: 'maintenance', fromTs: WM, untilTs: WM + 1000, note: 'n'.repeat(256) },
      WM,
    ),
  );
  rejects(book, () => add(book, 'cam', spec('reboot', WM, WM + 1000), WM));
  rejects(book, () => add(book, '', spec('maintenance', WM, WM + 1000), WM));
  rejects(book, () => add(book, 'cam', spec('maintenance', WM, WM), WM));
  rejects(book, () => add(book, 'cam', spec('maintenance', WM, WM + 1000), -1));
  const detectors = Array.from({ length: 257 }, (_, i) => `d${i}`);
  rejects(book, () =>
    add(book, 'cam', { kind: 'maintenance', fromTs: WM, untilTs: WM + 1000, detectors }, WM),
  );
  const payload = JSON.parse(
    `{"__proto__":{"x":1},"kind":"maintenance","fromTs":${WM},"untilTs":${WM + 1000}}`,
  );
  const before = structuredClone(toJSON(book));
  assert.throws(() => add(book, 'cam', payload, WM), /forbidden key/);
  assert.deepStrictEqual(toJSON(book), before);
});

test('hard rules and the never-affected detectors are not covered', () => {
  const book = createAnnotationBook();
  const until = WM + 3600e3;
  add(
    book,
    'cam',
    {
      kind: 'maintenance',
      fromTs: WM,
      untilTs: until,
      detectors: ['horizontal-scan', 'threat-intel-match'],
    },
    WM,
  );
  add(book, '*', spec('firmware-update', WM, until), WM);
  const ts = WM + 1000;
  assert.strictEqual(covers(book, 'cam', 'horizontal-scan', ts, false), true);
  assert.strictEqual(covers(book, 'cam', 'horizontal-scan', ts, true), false);
  assert.strictEqual(covers(book, 'cam', 'threat-intel-match', ts, false), false);
  assert.strictEqual(covers(book, 'other', 'beacon-change', ts, false), true);
  assert.strictEqual(covers(book, 'other', 'beacon-change', until, false), false);
  for (const id of NEVER) {
    assert.strictEqual(covers(book, 'cam', id, ts, false), false);
    assert.strictEqual(covers(book, 'other', id, ts, false), false);
  }
  const listed = ['beacon-change'];
  const lockId = add(
    book,
    'lock',
    { kind: 'user-action', fromTs: WM, untilTs: until, detectors: listed },
    WM,
  );
  listed.push('horizontal-scan');
  const lock = list(book, { device: 'lock' }).find((row) => row.id === lockId);
  assert.ok(lock);
  assert.deepStrictEqual(lock.detectors, ['beacon-change']);
  assert.strictEqual(covers(book, 'lock', 'beacon-change', ts, false), true);
});

test('list filters by device and by the active half-open window', () => {
  const book = createAnnotationBook();
  add(book, 'cam', spec('maintenance', WM, WM + 2000), WM);
  add(book, '*', spec('network-change', WM + 5000, WM + 6000), WM + 5000);
  assert.strictEqual(list(book, { device: 'cam' }).length, 2);
  assert.strictEqual(list(book, { device: '*' }).length, 1);
  assert.strictEqual(list(book, { device: 'cam', activeAt: WM }).length, 1);
  assert.strictEqual(list(book, { device: 'cam', activeAt: WM + 2000 }).length, 0);
  assert.strictEqual(
    list(book, { activeAt: WM + 5000 })
      .map((row) => row.target)
      .join(','),
    '*',
  );
});

test('abuse counts adds in 7 days and * uses on one UTC day', () => {
  const week = 7 * DAY;
  const early = 40 * DAY;
  const late = early + week + 1;
  const book = createAnnotationBook();
  add(book, 'cam', spec('user-action', early, early + 1000), early);
  for (let i = 0; i < 10; i++) add(book, 'cam', spec('user-action', late, late + 1000), late);
  assert.deepStrictEqual(abuse(book, 'cam', late), { deviceSpam: false, starSpam: false });
  add(book, 'cam', spec('user-action', late, late + 1000), late);
  assert.deepStrictEqual(abuse(book, 'cam', late), { deviceSpam: true, starSpam: false });
  for (const row of list(book, { device: 'cam' })) remove(book, row.id);
  assert.strictEqual(list(book, {}).length, 0);
  assert.deepStrictEqual(abuse(book, 'cam', late), { deviceSpam: true, starSpam: false });

  const stars = createAnnotationBook();
  const day = 12 * DAY;
  add(stars, '*', spec('network-change', day, day + 1000), day);
  add(stars, '*', spec('network-change', day + 10, day + 1010), day + 10);
  assert.deepStrictEqual(abuse(stars, 'cam', day + 10), { deviceSpam: false, starSpam: false });
  add(stars, '*', spec('network-change', day + 20, day + 1020), day + 20);
  assert.deepStrictEqual(abuse(stars, 'cam', day + 20), { deviceSpam: false, starSpam: true });
  assert.deepStrictEqual(abuse(stars, 'cam', day + DAY), { deviceSpam: false, starSpam: false });
});

test('abuse history keeps at most 64 stamps per device and 256 for *', () => {
  const book = createAnnotationBook();
  const base = 50 * DAY;
  for (let i = 0; i < 65; i++) {
    const at = base + i;
    const id = add(book, 'cam', spec('user-action', at, at + 1000), at);
    assert.strictEqual(remove(book, id), true);
  }
  const times = toJSON(book)
    .adds.filter((row) => row.target === 'cam')
    .map((row) => row.at);
  assert.strictEqual(times.length, 64);
  assert.strictEqual(times[0], base + 1);
  assert.strictEqual(times[63], base + 64);
  assert.strictEqual(abuse(book, 'cam', base + 64).deviceSpam, true);

  const stars = createAnnotationBook();
  for (let i = 0; i < 257; i++) {
    const at = base + i;
    const id = add(stars, '*', spec('network-change', at, at + 1000), at);
    assert.strictEqual(remove(stars, id), true);
  }
  assert.strictEqual(toJSON(stars).adds.length, 256);
});

test('ended firmware is listed once until it is marked suggested', () => {
  const book = createAnnotationBook();
  const until = WM + 5000;
  const open = add(book, 'cam', spec('firmware-update', WM, until), WM);
  const done = add(book, 'cam', spec('firmware-update', WM, WM + 1000), WM);
  add(book, 'cam', spec('maintenance', WM, WM + 1000), WM);
  assert.deepStrictEqual(endedFirmware(book, WM + 999), []);
  const ended = endedFirmware(book, WM + 1000);
  assert.deepStrictEqual(
    ended.map((row) => row.id),
    [done],
  );
  assert.deepStrictEqual(
    endedFirmware(book, until).map((row) => row.id),
    [open, done],
  );
  assert.strictEqual(markSuggested(book, done), true);
  assert.strictEqual(markSuggested(book, done), true);
  assert.deepStrictEqual(
    endedFirmware(book, until).map((row) => row.id),
    [open],
  );
  assert.strictEqual(markSuggested(book, 'missing'), false);
  assert.strictEqual(remove(book, open), true);
  assert.strictEqual(remove(book, open), false);
  assert.deepStrictEqual(endedFirmware(book, until), []);
});

test('round-trip keeps annotations, coverage, abuse, and ended firmware', () => {
  const book = createAnnotationBook();
  add(
    book,
    'cam',
    {
      kind: 'maintenance',
      fromTs: WM,
      untilTs: WM + 4000,
      detectors: ['beacon-change'],
      note: 'swap the camera',
      operator: 'ada',
    },
    WM,
  );
  const firmware = add(book, 'cam', spec('firmware-update', WM - 2000, WM - 1), WM);
  add(
    book,
    '*',
    { kind: 'network-change', fromTs: WM, untilTs: WM + 1000, detectors: ['nxdomain-burst'] },
    WM,
  );
  assert.strictEqual(markSuggested(book, firmware), true);
  const raw = JSON.parse(JSON.stringify(toJSON(book)));
  const copy = fromJSON(raw);
  assert.deepStrictEqual(toJSON(copy), toJSON(book));
  assert.deepStrictEqual(
    list(copy, { device: 'cam', activeAt: WM + 10 }),
    list(book, { device: 'cam', activeAt: WM + 10 }),
  );
  assert.strictEqual(covers(copy, 'cam', 'beacon-change', WM + 10, false), true);
  assert.strictEqual(covers(copy, 'cam', 'horizontal-scan', WM + 10, false), false);
  assert.deepStrictEqual(abuse(copy, 'cam', WM), abuse(book, 'cam', WM));
  assert.deepStrictEqual(endedFirmware(copy, WM), endedFirmware(book, WM));
  raw.items[0].fromTs = 1;
  assert.notStrictEqual(list(copy, {})[0].fromTs, 1);
});

test('fromJSON rejects a cap breach and a forbidden key before building a book', () => {
  const book = createAnnotationBook();
  add(book, 'cam', spec('maintenance', WM, WM + 1000), WM);
  const live = structuredClone(toJSON(book));
  const raw = structuredClone(live);
  raw.items[0].untilTs = raw.items[0].fromTs + 72 * 3600e3 + 1;
  assert.throws(
    () => fromJSON(raw),
    (err) => {
      assert.ok(err instanceof HubvikError);
      assert.strictEqual(err.code, 'ANNOTATION_INVALID');
      return true;
    },
  );
  const crowded = structuredClone(live);
  crowded.items = Array.from({ length: 65 }, (_, i) => ({ ...live.items[0], id: `a${i + 1}` }));
  crowded.next = 66;
  assert.throws(
    () => fromJSON(crowded),
    (err) => {
      assert.ok(err instanceof HubvikError);
      assert.strictEqual(err.code, 'ANNOTATION_INVALID');
      return true;
    },
  );
  assert.throws(
    () => fromJSON(JSON.parse('{"__proto__":{"x":1},"next":1,"items":[],"adds":[]}')),
    /forbidden key/,
  );
  assert.deepStrictEqual(toJSON(book), live);
});
