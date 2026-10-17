'use strict';

/**
 * Population mean, standard deviation, and max. Empty input is all zeros.
 * @param {any} values
 * @returns {{ n: number, mean: number, std: number, max: number }}
 */
function summarize(values) {
  const n = values.length;
  if (n === 0) return { n: 0, mean: 0, std: 0, max: 0 };
  const at = !Array.isArray(values) && typeof values.at === 'function';
  /**
   * @param {number} index
   * @returns {number}
   */
  function read(index) {
    return at ? values.at(index) : /** @type {number[]} */ (values)[index];
  }
  let sum = 0;
  let max = 0;
  for (let i = 0; i < n; i++) {
    const value = read(i);
    sum += value;
    if (value > max) max = value;
  }
  const mean = sum / n;
  let acc = 0;
  for (let i = 0; i < n; i++) {
    const diff = read(i) - mean;
    acc += diff * diff;
  }
  return { n, mean, std: Math.sqrt(acc / n), max };
}

module.exports = { summarize };
