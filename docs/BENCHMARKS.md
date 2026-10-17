# Benchmarks

Measured by `node bench/run.js` on 2026-10-17. All tiers on. 1,000 warmup feeds, then 10,000 timed feeds across 100 devices.

| Metric            | Budget   | Measured |
| ----------------- | -------- | -------- |
| median `feed()`   | < 10 µs  | 24.29 µs |
| memory per device | < 100 KB | 2.46 KB  |

Checkpoint B gate, same script, 2026-10-17: median 25.75 µs, 2.46 KB/device.
