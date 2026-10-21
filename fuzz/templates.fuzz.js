'use strict';

const { compile } = require('../packages/core/src/engine/templates');

const known = new Set(['new-destination', 'horizontal-scan']);

/**
 * @param {number} seed
 */
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = mulberry32(20261021);
let rejected = 0;
for (let i = 0; i < 100000; i += 1) {
  const id = rand() < 0.5 ? 'ok' : 12;
  const detector = rand() < 0.5 ? 'new-destination' : 'nope';
  try {
    compile(
      [
        {
          id,
          steps: [{ detector }],
          within: rand() < 0.5 ? '1h' : '9d',
          by: 'device',
        },
      ],
      known,
    );
  } catch {
    rejected += 1;
  }
}
if (rejected === 0) {
  console.error('templates fuzz rejected nothing');
  process.exit(1);
}
console.log(`templates fuzz: ${rejected} rejected`);
