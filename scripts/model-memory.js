'use strict';

const { createBloom } = require('../packages/core/src/engine/stats/bloom');
const { createForest } = require('../packages/core/src/engine/stats/hstree');

const one = createBloom();
const pair = [createBloom(), createBloom()];
const forest = createForest(1);

/**
 * @param {ArrayBufferView} view
 * @returns {number}
 */
function bufferByteLength(view) {
  return Buffer.from(view.buffer, view.byteOffset, view.byteLength).byteLength;
}

const oneBits = one.bits.byteLength;
const twoBits = pair[0].bits.byteLength + pair[1].bits.byteLength;
const mass = forest.mass.byteLength;
const lo = forest.lo.byteLength;
const hi = forest.hi.byteLength;

console.log(`one bloom bits byteLength ${oneBits}`);
console.log(`one bloom bits Buffer.byteLength ${bufferByteLength(one.bits)}`);
console.log(`two bloom bits byteLength ${twoBits}`);
console.log(
  `two bloom bits Buffer.byteLength ${bufferByteLength(pair[0].bits) + bufferByteLength(pair[1].bits)}`,
);
console.log(`forest mass byteLength ${mass}`);
console.log(`forest mass Buffer.byteLength ${bufferByteLength(forest.mass)}`);
console.log(`forest lo byteLength ${lo}`);
console.log(`forest lo Buffer.byteLength ${bufferByteLength(forest.lo)}`);
console.log(`forest hi byteLength ${hi}`);
console.log(`forest hi Buffer.byteLength ${bufferByteLength(forest.hi)}`);
console.log(`forest typed arrays byteLength ${mass + lo + hi}`);
