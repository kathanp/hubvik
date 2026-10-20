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

## WP-9.8 — 7-day heap profile

`node --expose-gc bench/heap-one.js`. 16 devices, two of each class, the same 7-day rich traffic and `lock()` as the 200-device bench. Heap is `heapUsed` after two `global.gc()` calls, minus the heap before those devices were created. Each row is that baseline minus the same run with one detector disabled. Runs were sequential. A parallel sweep moved the smaller rows by several KB, so those numbers are not used. Baseline runs: 463.31 KB/device and 463.99 KB/device. Deltas use their mean, 463.65 KB/device.

Closed windows are not kept. Window history is the per-window sample rings. Hourly history is the 24 rings in `volume-spike-hourly`. With every detector disabled the same 16 devices retain 34.29 KB/device, which is the device record and the open window, plus process overhead spread across 16 devices. LAN scratch is outside this table: `dhcp-starvation` 1.44 KB, `arp-spoof` 1.19 KB, `lan-lateral` 0.99 KB, `identity-change` 0.20 KB.

| Rank | Structure                                      | KB/device |
| ---- | ---------------------------------------------- | --------: |
| 1    | `volume-spike-hourly` hourly rings             |    107.84 |
| 2    | `volume-spike` window byte history             |     98.70 |
| 3    | `fan-out` window destination-count history     |     97.86 |
| 4    | `upload-ratio-shift` window ratio history      |     19.89 |
| 5    | `update-over-cleartext`                        |     12.99 |
| 6    | `failed-connection-ratio` window ratio history |     10.63 |
| 7    | `beacon-change`                                |      4.83 |
| 8    | `egress-flood`                                 |      3.64 |
| 9    | `answer-drift`                                 |      3.63 |
| 10   | `horizontal-scan`                              |      3.00 |
| 11   | `class-violation`                              |      2.66 |
| 12   | `long-connection`                              |      2.37 |
| 13   | `threat-intel-match`                           |      2.36 |
| 14   | `dns-tunnel`                                   |      2.29 |
| 15   | `slow-exfil`                                   |      2.28 |

The same tree's 200-device run, before the representation changes: median 6.75 µs, heap 374.99 KB/device, 6,947,350 events. These per-structure bytes are the part that scales with devices. The three history rows are 304.40 KB of that total.

## WP-9.8 — representation, remeasured

Sample rings now store samples in a `Float64Array`. `toArray()` is still a plain array, and `exportBaseline()` is unchanged. `git diff d4a742f -- test/diff/golden.json` is empty. Repeated destination strings are interned up to the existing destination cap. A device reuses its open window, one idle window, and one close summary. No threshold, cap, or default changed.

`bench/run.js` adds `arrayBuffers` to the byte count. A Float64Array's storage is not in `heapUsed`. The 100 KB check uses the sum.

16 devices, retained = heap + ArrayBuffers:

| After         |  retained KB/device |
| ------------- | ------------------: |
| typed arrays  |              398.23 |
| string intern | 396.83, then 397.77 |
| window reuse  |              398.37 |

Ring rows after the typed arrays, same 16-device disable measurement. The buffer column is the Float64Array storage.

| Structure                 | retained KB |    was |
| ------------------------- | ----------: | -----: |
| `volume-spike-hourly`     |       86.72 | 107.84 |
| `volume-spike`            |       80.17 |  98.70 |
| `fan-out`                 |       80.10 |  97.86 |
| `upload-ratio-shift`      |       14.80 |  19.89 |
| `failed-connection-ratio` |        9.12 |  10.63 |

200 devices after all three fixes: median 8.13 µs, retained 307.64 KB/device, 6,947,350 events. The 1,000-device line in the same process: median 6.25 µs, retained 16.96 KB/device. The 7-day figure is over 100 KB. Caps and the 100 KB budget were not changed.

## WP-11 — after streaming stats, 2026-10-18

`volume-spike`, `fan-out`, and `volume-spike-hourly` keep a Welford summary (count, mean, M2, max) instead of the sample rings. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.58 µs | 11.64 KB/device |
| 200 devices, 7 days, then `lock()` |         9.38 µs | 66.96 KB/device |

Events in the 7-day run: 6,947,350. Retained is heap plus ArrayBuffers. The 100 KB budget holds. Caps were not changed.

`update-over-cleartext` stores `{ fired: boolean }`. The 12.99 KB row above is the WP-9.8 disable-one heap delta, not a sample ring. `beacon-change` stores a `learned` map of gaps and a `tracks` map of open gaps. Neither detector was rewritten. `upload-ratio-shift` still keeps a ring capped at 2,048 and `failed-connection-ratio` a ring capped at 1,024. A 7-day learn is longer than those caps, so replacing the ring with a Welford of every learning window would not match the stored samples in `test/diff/golden.json`. Those two rings stay.

## WP-12 — shadow detectors running, 2026-10-18

`exploit-probe-http`, `young-domain`, and `ttl-anomaly` are enabled in shadow mode. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.79 µs | 11.68 KB/device |
| 200 devices, 7 days, then `lock()` |        13.54 µs | 68.07 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-13 — streaming statistics library, 2026-10-18

No detector moved onto the new primitives. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.96 µs | 11.68 KB/device |
| 200 devices, 7 days, then `lock()` |        10.29 µs | 68.06 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-14 — metamorphic suite, 2026-10-18

A checkpoint now also stores live detector state. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         7.08 µs | 11.55 KB/device |
| 200 devices, 7 days, then `lock()` |         8.92 µs | 67.99 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-14.1 — reorder buffer, 2026-10-18

`reorderMs` stays 0 on the 7-day line, so that run does not allocate a buffer. `node --expose-gc bench/run.js` then printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.42 µs | 11.67 KB/device |
| 200 devices, 7 days, then `lock()` |         6.96 µs | 68.11 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

`node --expose-gc bench/reorder.js` is the same 1,000-device line with `reorderMs: 5000`. Median `feed()` was 6.08 µs. Retained memory was 8.63 KB/device after `lock()` released the buffer, and 11.34 KB/device while the buffer still held the last 5 seconds of events.

## WP-15 — explainability, 2026-10-18

`explain()` stores one object per anomaly, capped at 1,000 for the whole engine. The 7-day line does not fill that cap. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.92 µs | 11.69 KB/device |
| 200 devices, 7 days, then `lock()` |         7.79 µs | 68.15 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-16 — identity, 2026-10-18

The identity table is off unless `identity` is `'auto'`. The 7-day bench leaves it off. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.46 µs | 11.70 KB/device |
| 200 devices, 7 days, then `lock()` |         6.50 µs | 68.37 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-17 — feedback and promotion, 2026-10-18

`promote` is off in this bench, so candidates are not stored. The feedback ring is empty. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.75 µs | 11.70 KB/device |
| 200 devices, 7 days, then `lock()` |         9.63 µs | 68.34 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-18 — learning-poison guards, 2026-10-18

The three new warnings count during learning and do not add a per-destination table on the 7-day line (`learnMs` is far longer than the run, so the last third and the midpoint are never reached). `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.42 µs | 11.98 KB/device |
| 200 devices, 7 days, then `lock()` |         7.92 µs | 68.67 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## 0.7.0 release gate, 2026-10-18

`npm run gate` on core 0.7.0 exited 0, then `npm run demo`. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.88 µs | 11.98 KB/device |
| 200 devices, 7 days, then `lock()` |         6.71 µs | 68.69 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed.

## WP-18.1 — pack cap, 2026-10-18

No detector state changed. `node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.63 µs | 11.98 KB/device |
| 200 devices, 7 days, then `lock()` |         6.92 µs | 68.70 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. Caps were not changed. Core unpacked size was 463,378 bytes.

## WP-19 — horizons, 2026-10-18

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.17 µs | 11.99 KB/device |
| 200 devices, 7 days, then `lock()` |         6.54 µs | 84.43 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The hourly ring is on for that run because T1 is on and the new shadow detectors are enabled. Caps were not changed.

## WP-20 — LAN graph, 2026-10-18

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.42 µs | 12.04 KB/device |
| 200 devices, 7 days, then `lock()` |         6.54 µs | 85.51 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The graph is on because the graph detectors are enabled. Campaigns stay off. Caps were not changed.

## WP-21 — remaining shadow detectors, 2026-10-19

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         7.17 µs | 12.04 KB/device |
| 200 devices, 7 days, then `lock()` |        10.13 µs | 87.35 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The new detectors are enabled and shadow. Caps were not changed.

## WP-22 — rule language, 2026-10-19

`node --expose-gc bench/run.js` printed:

| Line                               | median `feed()` |        retained |
| ---------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries       |         6.75 µs | 12.04 KB/device |
| 200 devices, 7 days, then `lock()` |        11.17 µs | 87.36 KB/device |

Events in the 7-day run: 6,948,925. Under 100 KB. The 1,000-device median is the gated watching budget (< 10 µs). Rules were not loaded. Caps were not changed.

## WP-21.5 — shadow detector heap, 2026-10-19

`node --expose-gc bench/heap-one.js`, 16 devices, sequential, every shadow detector still running. Retained is heap plus ArrayBuffers after two collections. Three baselines, median 205.42 KB/device. A row is that median minus the same run with one detector disabled. A second pass of three runs replaced the rows that moved by more than 1 KB, including `upnp-callstranger`, whose first run sat 29 KB the wrong way. Negative rows are inside the baseline spread.

| Detector                 | KB/device |
| ------------------------ | --------: |
| `multi-horizon-exfil`    |      4.58 |
| `slow-scan`              |      2.71 |
| `cloud-storage-exfil`    |      2.12 |
| `ttl-anomaly`            |      1.86 |
| `jitter-beacon`          |      1.80 |
| `exploit-then-download`  |      1.30 |
| `graph-role-change`      |      0.87 |
| `graph-new-bridge`       |      0.80 |
| `dhcpv6-rogue`           |      0.20 |
| `young-domain`           |      0.18 |
| `matter-new-controller`  |      0.07 |
| `evil-twin`              |      0.04 |
| `exploit-probe-http`     |      0.03 |
| `ssh-brute-then-session` |     -0.27 |
| `nd-spoof`               |     -0.31 |
| `upnp-callstranger`      |     -0.41 |
| `wifi-deauth-flood`      |     -0.52 |

Only `multi-horizon-exfil` is over 3 KB/device on this 16-device sweep. Its exported state is about 0.3 KB. The rest of the row is object overhead plus a fixed cost divided by 16 devices. After the typed-array pack, two baselines averaged 204.88 KB/device and two disabled runs averaged 201.00, so the row is 3.88 KB/device. Caps were not changed. Detector output was not changed.

## WP-21.5 — shadow option, 2026-10-19

`node --expose-gc bench/run.js` printed:

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         6.92 µs | 11.99 KB/device |
| 200 devices, 7 days, defaults       |         7.46 µs | 67.86 KB/device |
| 200 devices, 7 days, `shadow: true` |         9.92 µs | 74.39 KB/device |

Events in each 7-day run: 6,948,925. Both 7-day lines are under 100 KB. The 1,000-device median is under 10 µs. The `shadow: true` median, 9.92 µs, is within 1% of the 10 µs x86 budget. It is recorded and is not a gate. Shadow mode is not claimed budget-safe on a Raspberry Pi 4 until it is measured there. Defaults leave the horizon ring and the LAN graph off, because the detectors that turn them on are shadow. Caps were not changed.

## Alignment re-gate, 2026-10-20

`npm run gate` exited 0. `node --expose-gc bench/run.js` printed:

| Line                                | median `feed()` |        retained |
| ----------------------------------- | --------------: | --------------: |
| 1,000 devices, two summaries        |         7.29 µs | 12.01 KB/device |
| 200 devices, 7 days, defaults       |         9.33 µs | 68.13 KB/device |
| 200 devices, 7 days, `shadow: true` |        10.38 µs | 74.52 KB/device |

Events in each 7-day run: 6,948,925. Defaults stay under 10 µs and under 100 KB. The `shadow: true` median is over the 10 µs x86 line. It is still not a gate. Shadow mode is not claimed budget-safe on x86 from this run, and it is not claimed budget-safe on a Raspberry Pi 4 until it is measured there.

`multi-horizon-exfil` does not keep a second hourly ring. Learned hours are five numbers in a `Float64Array` (count, mean, M2, min, max) plus one P² sketch of daily totals. `check()` reads the last 24 hours from `ctx.horizon`, the same ring `slow-scan` uses. Turning this detector off does not shrink that ring while `slow-scan` is still running. The 3.88 KB sweep row is larger than the exported state (about 0.3 KB) because the 16-device sweep divides fixed allocator cost by 16.
