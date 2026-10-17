'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createEngine } = require('../src/index.js');

/**
 * @param {string} id
 * @param {string[] | undefined} consumes
 * @param {string[]} calls
 */
function plugin(id, consumes, calls) {
  return {
    id,
    version: 1,
    meta: consumes === undefined ? {} : { consumes },
    requires: ['T0'],
    hardRule: true,
    defaults: {},
    /** @param {any} _state @param {any} ev */
    check(_state, ev) {
      calls.push(`${id}:${ev.type}`);
    },
    onWindowClose() {
      calls.push(`${id}:close`);
    },
  };
}

test('feed dispatches only the event types a detector consumes', () => {
  /** @type {string[]} */
  const calls = [];
  const engine = createEngine({ learnMs: 60_000, tiers: ['T0'] });
  engine.use(plugin('only-dns', ['dns'], calls));
  engine.use(plugin('signals-only', [], calls));
  engine.use(plugin('every-type', undefined, calls));
  engine.feed({ device: 'd', dst: 'a.example', bytes: 1, ts: 0 });
  engine.feed({
    type: 'dns',
    device: 'd',
    ts: 1000,
    qname: 'a.example',
    qtype: 'A',
    rcode: 'NOERROR',
    resolver: '10.0.0.1',
  });
  engine.flush();
  assert.deepEqual(calls, [
    'every-type:summary',
    'only-dns:dns',
    'every-type:dns',
    'only-dns:close',
    'signals-only:close',
    'every-type:close',
  ]);
});

test('a detector consumes list rejects an unknown event type', () => {
  const engine = createEngine({ learnMs: 60_000, tiers: ['T0'] });
  assert.throws(
    () =>
      engine.use({
        id: 'bad-consumes',
        version: 1,
        meta: { consumes: ['packet'] },
        requires: ['T0'],
        defaults: {},
      }),
    /unknown event type/,
  );
});
