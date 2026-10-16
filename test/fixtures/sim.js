'use strict';

const { mulberry32, range } = require('./prng');
const { T0, H, DAY } = require('./clock');
const { PROFILES } = require('./profiles');

/**
 * @param {{ hosts: string[], hostPick?: string }} spec
 * @param {number} n
 * @returns {string}
 */
function pickHost(spec, n) {
  if (spec.hostPick === 'tenth') return n % 10 === 0 ? spec.hosts[1] : spec.hosts[0];
  if (spec.hostPick === 'mod') return spec.hosts[n % spec.hosts.length];
  return spec.hosts[0];
}

/**
 * T0 connection summaries for one benign device class.
 * @param {{ profile: string, days: number, seed?: number, startTs?: number }} opts
 * @returns {{ device: string, dst: string, bytes: number, ts: number }[]}
 */
function simulate(opts) {
  const spec = PROFILES[opts.profile];
  if (!spec) throw new Error(`unknown profile ${opts.profile}`);
  if (!Number.isInteger(opts.days) || opts.days < 1)
    throw new Error('days must be a positive integer');
  const rng = mulberry32(opts.seed ?? 1);
  const origin = opts.startTs ?? T0;
  const minuteLimit = (spec.minutes ?? 60) * 60_000;
  /** @type {{ device: string, dst: string, bytes: number, ts: number }[]} */
  const events = [];
  let n = 0;
  for (let day = 0; day < opts.days; day++) {
    for (const hour of spec.hours) {
      for (let ms = 0; ms < minuteLimit; ms += spec.everyMs) {
        const jitter = spec.jitter ?? 0;
        const scale = 1 + range(rng, -jitter, jitter);
        events.push({
          device: spec.device,
          dst: pickHost(spec, n),
          bytes: Math.max(1, Math.round(spec.bytes * scale)),
          ts: origin + day * DAY + hour * H + ms,
        });
        n += 1;
      }
    }
  }
  return events;
}

module.exports = { simulate };
