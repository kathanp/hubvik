# Benchmarks

Measured by `node bench/run.js`. The script exits non-zero when a budget is missed. Detectors were not tuned to pass.

## WP-8.1 — watching state, 2026-10-17

All tiers on. 1,000 devices. Each device gets one event at t=0 and one at `learnMs` (60 s), then `lock()`, then 10,000 timed `feed()` calls.

| Metric            | Budget   | Measured |
| ----------------- | -------- | -------- |
| median `feed()`   | < 10 µs  | 22.38 µs |
| memory per device | < 100 KB | 2.34 KB  |

The gate re-ran the same script: median 21.04 µs, 2.34 KB/device.

## WP-8.2 — CPU profile, 2026-10-17

`node --cpu-prof --cpu-prof-interval=100`. All tiers on. 1,000 devices past `learnMs`, then `lock()`, then 80,000 watching-state summary `feed()` calls. Self time is the profiler's leaf sample. 12,446 samples.

| Rank | Function              | Location                       | Self time |
| ---- | --------------------- | ------------------------------ | --------- |
| 1    | `_run`                | `engine/engine.js:845`         | 24.3%     |
| 2    | `_optionsFor`         | `engine/engine.js:112`         | 23.2%     |
| 3    | `feed`                | `engine/engine.js:185`         | 7.2%      |
| 4    | `_state`              | `engine/engine.js:162`         | 4.1%      |
| 5    | `(garbage collector)` | `(native)`                     | 2.5%      |
| 6    | `domainToASCII`       | `(native)`                     | 1.8%      |
| 7    | `(program)`           | `(native)`                     | 1.7%      |
| 8    | `torHit`              | `detectors/tor-or-proxy.js:56` | 1.3%      |
| 9    | `domainFamily`        | `engine/net.js:91`             | 1.1%      |
| 10   | `exactHit`            | `engine/indicators.js:50`      | 0.9%      |

## WP-8 — 100 devices, 2026-10-17

All tiers on. 1,000 warmup feeds, then 10,000 timed feeds across 100 devices. That script recorded the miss and did not fail the gate.

| Metric            | Budget   | Measured |
| ----------------- | -------- | -------- |
| median `feed()`   | < 10 µs  | 24.29 µs |
| memory per device | < 100 KB | 2.46 KB  |

Checkpoint B gate, same script, 2026-10-17: median 25.75 µs, 2.46 KB/device.
