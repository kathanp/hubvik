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

/**
 * Running count, mean, sum of squared deviations, and max.
 * @returns {{ count: number, mean: number, m2: number, max: number }}
 */
function emptyStats() {
  return { count: 0, mean: 0, m2: 0, max: 0 };
}

/**
 * Welford's update. Population deviation stays in `m2` so `sqrt(m2 / count)` matches `summarize`.
 * @param {{ count: number, mean: number, m2: number, max: number }} stats
 * @param {number} value
 * @returns {void}
 */
function pushSample(stats, value) {
  const count = stats.count + 1;
  const delta = value - stats.mean;
  const mean = stats.mean + delta / count;
  stats.m2 += delta * (value - mean);
  stats.mean = mean;
  stats.count = count;
  if (value > stats.max) stats.max = value;
}

/**
 * @param {number[]} values
 * @returns {{ count: number, mean: number, m2: number, max: number }}
 */
function statsFromValues(values) {
  const stats = emptyStats();
  for (let i = 0; i < values.length; i++) pushSample(stats, values[i]);
  return stats;
}

/**
 * @param {{ count: number, mean: number, m2: number, max: number }} stats
 * @returns {{ n: number, mean: number, std: number, max: number }}
 */
function statsOf(stats) {
  if (!stats || stats.count === 0) return { n: 0, mean: 0, std: 0, max: 0 };
  return {
    n: stats.count,
    mean: stats.mean,
    std: Math.sqrt(stats.m2 / stats.count),
    max: stats.max,
  };
}

module.exports = { summarize, emptyStats, pushSample, statsFromValues, statsOf };
