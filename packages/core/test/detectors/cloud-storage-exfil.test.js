'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../../src/index.js');
const { flow } = require('../../../../test/fixtures/flow');

const TIERS = ['T0', 'T1', 'T2'];

test('cloud-storage-exfil fires on a new object-storage upload over 10 MB', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: TIERS });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'cloud-storage-exfil') hits.push(row);
  });
  eng.feed(flow({ dstName: 'bucket.s3.amazonaws.com', bytesOut: 11 * 1024 * 1024 }));
  assert.equal(hits.length, 1);
  assert.equal(hits[0].data.pattern, 's3.amazonaws.com');
});

test('cloud-storage-exfil ignores a pattern seen while learning and AWS IoT names', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: TIERS });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'cloud-storage-exfil') hits.push(row);
  });
  eng.feed(flow({ ts: 1000, dstName: 'photos.s3.amazonaws.com', bytesOut: 1000 }));
  eng.feed(flow({ ts: 7000, dstName: 'photos.s3.amazonaws.com', bytesOut: 20 * 1024 * 1024 }));
  eng.feed(
    flow({ ts: 8000, dstName: 'abc.iot.us-east-1.amazonaws.com', bytesOut: 20 * 1024 * 1024 }),
  );
  assert.deepEqual(hits, []);
});

test('cloud-storage-exfil matches a one-label wildcard and a DNS name', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: TIERS });
  /** @type {any[]} */
  const hits = [];
  eng.on('shadow-anomaly', (row) => {
    if (row.detector === 'cloud-storage-exfil') hits.push(row);
  });
  eng.feed({
    type: 'dns',
    device: 'd',
    ts: 1000,
    qname: 'bucket.s3.eu-west-1.amazonaws.com',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  eng.feed(
    flow({
      ts: 2000,
      dstName: 'bucket.s3.eu-west-1.amazonaws.com',
      bytesOut: 11 * 1024 * 1024,
    }),
  );
  assert.equal(hits.length, 1);
  assert.equal(hits[0].data.pattern, 's3.*.amazonaws.com');
});

test('cloud-storage-exfil import rejects an oversized row list', () => {
  const eng = createEngine({ shadow: true, learnMs: 0, tiers: TIERS });
  eng.feed(flow({ ts: 1, dstName: 'x.blob.core.windows.net', bytesOut: 10 }));
  const saved = eng.exportBaseline({ createdAt: 1 });
  const rows = [];
  for (let i = 0; i < 8; i += 1) rows.push([`p${i}`, { seen: false }]);
  assert.throws(
    () =>
      eng.importBaseline({
        ...saved,
        devices: {
          d: {
            ...saved.devices.d,
            detectors: { 'cloud-storage-exfil': { v: 1, state: { rows } } },
          },
        },
      }),
    /exceeds cap/,
  );
});

test('cloud-storage-exfil survives export and import', () => {
  const eng = createEngine({ shadow: true, learnMs: 5000, tiers: TIERS });
  eng.feed(flow({ ts: 1000, dstName: 'x.blob.core.windows.net', bytesOut: 100 }));
  const saved = eng.exportBaseline();
  const next = createEngine({ shadow: true, learnMs: 0, tiers: TIERS });
  next.importBaseline(saved);
  assert.equal(
    next.exportBaseline().devices.d.detectors['cloud-storage-exfil'].state.rows.length,
    1,
  );
});
