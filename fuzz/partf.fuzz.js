'use strict';

const { createEngine } = require('../packages/core/src/index.js');
const { mulberry32 } = require('../test/fixtures/prng.js');

const N = 100_000;
const OPS = ['na', 'ns', 'rs', 'ra'];
const VERDICTS = ['tp', 'fp', 'benign-true', 'unknown', 'maybe'];

/**
 * @param {() => number} rng
 * @param {number} i
 */
function ndEvent(rng, i) {
  const kind = Math.floor(rng() * 5);
  const ts = i * 1_000;
  if (kind === 0) {
    return {
      type: 'nd',
      device: 'aa:bb:cc:dd:ee:01',
      ts,
      ip: `2001:db8::${i % 64}`,
      mac: 'aa:bb:cc:dd:ee:01',
      op: OPS[i % 4],
      router: i % 2 === 0,
    };
  }
  if (kind === 1) {
    return {
      type: 'nd',
      device: 'd',
      ts,
      ip: '1.2.3.4',
      mac: 'aa:bb:cc:dd:ee:01',
      op: 'na',
    };
  }
  if (kind === 2) {
    return {
      type: 'nd',
      device: 'd',
      ts,
      ip: '2001:db8::1',
      mac: 'not-a-mac',
      op: 'na',
    };
  }
  if (kind === 3) {
    return { type: 'nd', device: 'd', ts, ip: '2001:db8::1', mac: 'aa:bb:cc:dd:ee:01', op: 'no' };
  }
  return JSON.parse(
    `{"__proto__":{"x":${i}},"type":"nd","device":"d","ts":${ts},"ip":"2001:db8::1","mac":"aa:bb:cc:dd:ee:01","op":"na"}`,
  );
}

/**
 * @param {() => number} rng
 * @param {number} i
 * @param {string} knownId
 */
function feedbackCall(rng, i, knownId) {
  const key = rng() < 0.05 ? knownId : `nope-${i % 17}`;
  const verdict = VERDICTS[Math.floor(rng() * VERDICTS.length)];
  /** @type {Record<string, string> | undefined} */
  let opts;
  if (rng() < 0.2) opts = { operator: 'ada', note: 'fuzz' };
  if (rng() < 0.05) opts = JSON.parse(`{"__proto__":{"x":${i}},"operator":"ada"}`);
  return { key, verdict, opts };
}

const ndEngine = createEngine({ learnMs: 0, identity: 'auto', tiers: ['T0', 'T4'] });
const ndRng = mulberry32(20261018);
let ndRejected = 0;
for (let i = 0; i < N; i += 1) {
  try {
    ndEngine.feed(ndEvent(ndRng, i));
  } catch (err) {
    if (!(err instanceof Error)) throw err;
    ndRejected += 1;
  }
}
ndEngine.feed({
  type: 'nd',
  device: 'aa:bb:cc:dd:ee:01',
  ts: N * 1_000,
  ip: '2001:db8::99',
  mac: 'aa:bb:cc:dd:ee:01',
  op: 'na',
});
if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
console.log(`nd fuzz: ${N} inputs, ${ndRejected} rejected`);

const labelEngine = createEngine({ learnMs: 1000, tiers: ['T0'] });
/** @type {string} */
let knownId = '';
labelEngine.on('anomaly', (item) => {
  if (!knownId && item.detector === 'new-device') knownId = item.id;
});
labelEngine.feed({ device: 'seed', dst: 'a.example', bytes: 1, ts: 0 });
labelEngine.feed({ device: 'other', dst: 'a.example', bytes: 1, ts: 5000 });
if (!knownId) throw new Error('feedback fuzz needs an anomaly id');
const labelRng = mulberry32(20261020);
let labelRejected = 0;
for (let i = 0; i < N; i += 1) {
  const call = feedbackCall(labelRng, i, knownId);
  try {
    labelEngine.feedback(call.key, call.verdict, call.opts);
  } catch (err) {
    if (!(err instanceof Error)) throw err;
    labelRejected += 1;
  }
}
if (labelEngine.exportLabels().length === 0) throw new Error('feedback fuzz accepted nothing');
if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
console.log(`feedback fuzz: ${N} inputs, ${labelRejected} rejected`);

const source = createEngine({ learnMs: 0, reorderMs: 5000, tiers: ['T0'] });
source.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 1000 });
source.feed({ device: 'd', dst: 'b.example', bytes: 1, ts: 2000 });
const saved = source.checkpoint({ createdAt: 1 });
if (!Array.isArray(saved.reorder) || saved.reorder.length === 0) {
  throw new Error('reorder fuzz needs a buffered checkpoint');
}
const over = JSON.parse(JSON.stringify(saved));
over.reorder = Array.from({ length: 50_001 }, () => over.reorder[0]);
const probe = createEngine({ learnMs: 0, reorderMs: 5000, tiers: ['T0'] });
try {
  probe.restore(over);
  throw new Error('reorder over cap was accepted');
} catch (err) {
  if (!(err instanceof Error) || !/exceeds cap/.test(err.message)) throw err;
}

const restoreEngine = createEngine({ learnMs: 0, reorderMs: 5000, tiers: ['T0'] });
restoreEngine.feed({ device: 'keep', dst: 'a.example', bytes: 1, ts: 0 });
const reorderRng = mulberry32(20261021);
let reorderRejected = 0;
for (let i = 0; i < N; i += 1) {
  const body = JSON.parse(JSON.stringify(saved));
  const kind = Math.floor(reorderRng() * 5);
  if (kind === 0) body.reorder = null;
  else if (kind === 1) body.reorder.reverse();
  else if (kind === 2) body.reorder.push({ seq: -1, event: { device: 'd', ts: 1 } });
  else if (kind === 3) {
    body.reorder[0].event = JSON.parse(`{"__proto__":{"x":${i}},"device":"d","ts":1}`);
  }
  const before = restoreEngine.stats().events;
  try {
    restoreEngine.restore(body);
  } catch (err) {
    if (restoreEngine.stats().events !== before) {
      throw new Error('restore changed state', { cause: err });
    }
    if (!(err instanceof Error)) throw err;
    reorderRejected += 1;
  }
}
if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
console.log(`reorder restore fuzz: ${N} inputs, ${reorderRejected} rejected`);
