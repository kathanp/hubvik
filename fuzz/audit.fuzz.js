'use strict';

const {
  createAuditLog,
  append,
  fromJSON,
  verifyAudit,
} = require('../packages/core/src/engine/audit');
const { HubvikError } = require('../packages/core/src/errors');
const { mulberry32 } = require('../test/fixtures/prng');

const N = 100_000;
const ZERO = '0'.repeat(64);
const rng = mulberry32(20261021);

/**
 * @param {{ records: { hash: string }[], nextSeq: number, anchor: string, key: string | null }} log
 */
function snap(log) {
  const last = log.records.length === 0 ? '' : log.records[log.records.length - 1].hash;
  return `${log.records.length}|${log.nextSeq}|${log.anchor}|${String(log.key)}|${last}`;
}

/**
 * @returns {unknown}
 */
function badInput() {
  const defect = Math.floor(rng() * 8);
  if (defect === 0) return null;
  if (defect === 1) return [];
  if (defect === 2) return { ts: 1, kind: 'not-a-kind' };
  if (defect === 3) return { ts: -1, kind: 'allow' };
  if (defect === 4) return { ts: 1, kind: 'allow', extra: true };
  if (defect === 5) {
    const obj = { ts: 1, kind: 'allow', args: {} };
    obj.args = obj;
    return obj;
  }
  if (defect === 6) return JSON.parse('{"__proto__":{"x":1},"ts":1,"kind":"allow"}');
  const inherited = { ts: 'soon', kind: 'allow' };
  inherited['__proto__'] = { x: 1 };
  return inherited;
}

/**
 * @returns {unknown}
 */
function badOpts() {
  const pick = Math.floor(rng() * 4);
  if (pick === 0) return undefined;
  if (pick === 1) return { key: 1 };
  if (pick === 2) return { key: 'k', extra: true };
  return [];
}

/**
 * @returns {unknown}
 */
function badState() {
  const defect = Math.floor(rng() * 6);
  if (defect === 0) return null;
  if (defect === 1) return [];
  if (defect === 2) return { anchor: '00', nextSeq: 0, records: [] };
  if (defect === 3) return { anchor: ZERO, nextSeq: -1, records: [] };
  if (defect === 4) return { anchor: ZERO, nextSeq: 0, records: [{}] };
  return JSON.parse(`{"__proto__":{"x":1},"anchor":"${ZERO}","nextSeq":0,"records":[]}`);
}

const log = createAuditLog();
append(log, { ts: 0, kind: 'allow', operator: 'op', target: 't', args: { a: 1 } });
let rejected = 0;

for (let i = 0; i < N; i += 1) {
  const before = snap(log);
  const mode = rng() < 0.5 ? 'append' : 'fromJSON';
  try {
    if (mode === 'append') append(log, badInput(), badOpts());
    else fromJSON(log, badState());
    console.error(`audit fuzz accepted invalid input ${i}`);
    process.exit(1);
  } catch (err) {
    if (!(err instanceof HubvikError)) throw err;
    if (snap(log) !== before) throw new Error('audit fuzz mutated state', { cause: err });
    rejected += 1;
  }
}

if (Object.hasOwn(Object.prototype, 'x')) throw new Error('prototype polluted');
if (!verifyAudit(log).ok) throw new Error('seed record no longer verifies');
if (rejected === 0) {
  console.error('audit fuzz accepted every input');
  process.exit(1);
}
console.log(`audit fuzz: ${N} inputs, ${rejected} rejected`);
