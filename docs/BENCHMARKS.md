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

## WP-8.2 — dispatch, 2026-10-17

Same script as WP-8.1: all tiers, 1,000 devices, past `learnMs`, `lock()`, then 10,000 timed summary `feed()` calls. The 10 µs budget is unchanged.

|            | median `feed()` | memory per device |
| ---------- | --------------- | ----------------- |
| Before     | 22.38 µs        | 2.34 KB           |
| Gate rerun | 21.04 µs        | 2.34 KB           |
| After      | 6.04 µs         | 1.19 KB           |

Before is the WP-8.1 measurement. After is `node bench/run.js` once `feed()` dispatches by `meta.consumes`. The script exited 0. The gate re-ran it: median 6.13 µs, 1.19 KB/device.

`bench/run.js` did not change between those runs. The serialized baseline did not change either: `test/diff/dispatch.test.js` replays every replay test, both attack generators, and the all-tier benign matrix (seeds 1–3) and matches the anomaly stream and `exportBaseline()` captured at `0a1755b`, the commit before dispatch. The KB drop is which detector states `feed()` allocates. `stats().memoryBytes` sums `memoryEstimate` only for states a feed has created. A summary event no longer creates state for a detector whose `consumes` list omits `summary`. `exportBaseline()` still writes a fresh state for those detectors, and that fresh state matches what their learn/check produced on a summary they ignore.

## WP-8 — 100 devices, 2026-10-17

All tiers on. 1,000 warmup feeds, then 10,000 timed feeds across 100 devices. That script recorded the miss and did not fail the gate.

| Metric            | Budget   | Measured |
| ----------------- | -------- | -------- |
| median `feed()`   | < 10 µs  | 24.29 µs |
| memory per device | < 100 KB | 2.46 KB  |

Checkpoint B gate, same script, 2026-10-17: median 25.75 µs, 2.46 KB/device.

## WP-9.4 — measured heap, 2026-10-17

`node --expose-gc bench/run.js`. All tiers, 1,000 devices, `lock()`, then `process.memoryUsage().heapUsed` after `global.gc()`, minus the heap before those devices were created. The 100 KB budget checks this heap delta. `memoryEstimate` is still printed. It does not decide the budget. Detectors were not tuned.

| Host           | median `feed()` | memoryEstimate | measured heap |
| -------------- | --------------- | -------------- | ------------- |
| x86            | 5.83 µs         | 1.19 KB        | 12.33 KB      |
| Raspberry Pi 4 | not measured    | not measured   | not measured  |

## WP-9.6 — estimate versus heap

Each of the 1,000 bench devices learned 2 summary events, at `ts` 0 and `ts` 60000, before the heap delta. The timed `feed()` loop runs after that sample.

`memoryEstimate` for the five largest underestimates now counts structures that were already allocated: `volume-spike-hourly` counts its 24 `SampleRing` objects, and `blockchain-c2`, `tor-or-proxy`, `cryptomining`, and `tunnel-service` count two empty `LruSet`s each (240 bytes for the object and its `Map`, measured on Node 24). Their stored state was not changed. The WP-9.6 gate printed median 5.46 µs, estimate 5.70 KB/device, heap 12.27 KB/device. Heap / estimate is 2.15. That is outside 2×. The remaining gap is the other detector objects plus the device record. Closing it by shrinking the 24 hourly rings would change state, so the rings stay.

Fresh-state heap is `createState` measured with `node --expose-gc`. `memoryEstimate` is the bench state after those 2 events. `volume-spike-hourly` holds one sample by then, so its estimate is higher than the empty-ring measurement.

| Detector                | fresh-state heap (bytes) | memoryEstimate (bytes) | heap / estimate |
| ----------------------- | -----------------------: | ---------------------: | --------------: |
| volume-spike-hourly     |                    2,414 |                  2,712 |            0.89 |
| blockchain-c2           |                      503 |                    512 |            0.98 |
| tunnel-service          |                      502 |                    512 |            0.98 |
| tor-or-proxy            |                      496 |                    512 |            0.97 |
| cryptomining            |                      496 |                    512 |            0.97 |
| new-domain-family       |                      496 |                     80 |            6.21 |
| new-destination         |                      510 |                    128 |            3.98 |
| wrong-time              |                      424 |                     40 |           10.61 |
| peer-divergence         |                      354 |                     40 |            8.86 |
| threat-intel-match      |                      264 |                      0 |          no est |
| proxy-sdk-traffic       |                      264 |                      0 |          no est |
| class-violation         |                      234 |                     32 |            7.32 |
| went-silent             |                      218 |                     40 |            5.45 |
| policy-violation        |                      201 |                      0 |          no est |
| fleet-wave              |                      194 |                     40 |            4.84 |
| failed-connection-ratio |                      157 |                     32 |            4.92 |
| upload-ratio-shift      |                      156 |                     32 |            4.88 |
| nxdomain-burst          |                      150 |                     32 |            4.68 |
| fan-out                 |                      139 |                     40 |            3.48 |
| volume-spike            |                      136 |                     40 |            3.41 |
| protocol-mix-shift      |                       73 |                     24 |            3.06 |
| ot-write-rate           |                       59 |                     16 |            3.67 |
| connection-churn        |                       57 |                     16 |            3.59 |
| new-device              |                       41 |                     16 |            2.59 |
| clock-jump              |                       41 |                     16 |            2.59 |

## WP-9.7 — 200 devices, 7 days rich, 2026-10-17

`node --expose-gc bench/run.js`, after the 1,000-device check. 200 devices, classes rotated through the simulator profiles. Each device is fed 7 days of rich traffic, then `lock()`. Heap is `heapUsed` after `global.gc()`, minus the heap before those devices were created. The watching median is 2,000 summary `feed()` calls after lock. Detectors were not tuned.

The same process printed the 1,000-device line first: median 5.33 µs, estimate 5.70 KB/device, heap 12.27 KB/device.

| Metric            | Budget   | Measured  |
| ----------------- | -------- | --------- |
| median `feed()`   | reported | 6.38 µs   |
| memory per device | < 100 KB | 374.99 KB |
| devices           | 200      | 200       |
| events fed        |          | 6,947,350 |

The heap is over 100 KB per device. The script exits non-zero. No threshold was changed.
