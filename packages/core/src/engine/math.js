'use strict';

/**
 * Population mean, standard deviation, and max. Empty input is all zeros.
 * @param {number[] | { toArray: () => number[] }} values
 * @returns {{ n: number, mean: number, std: number, max: number }}
 */
function summarize(values) {
  const list = Array.isArray(values) ? values : values.toArray();
  const n = list.length;
  if (n === 0) return { n: 0, mean: 0, std: 0, max: 0 };
  let sum = 0;
  let max = 0;
  for (let i = 0; i < n; i++) {
    const value = list[i];
    sum += value;
    if (value > max) max = value;
  }
  const mean = sum / n;
  let acc = 0;
  for (let i = 0; i < n; i++) {
    const diff = list[i] - mean;
    acc += diff * diff;
  }
  return { n, mean, std: Math.sqrt(acc / n), max };
}

module.exports = { summarize };
